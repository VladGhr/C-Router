#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h>
#include <string.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ETHER_HW_TYPE 1
#define ICMP_TIME_EXCEEDED 11
#define ICMP_DEST_UNREACH 3
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0
#define ICMP_HDR_CPY_LEN 8
#define DEFAULT_TTL 64
#define MAX_RTB_SIZE 80000
#define MAX_ARP_SIZE 1000

struct route_table_entry rtable[MAX_RTB_SIZE];

struct trie_node {
	struct trie_node *left;
	struct trie_node *right;
	struct route_table_entry *route;
};

struct queued_packet {
	char *packet;
	size_t len;
};

struct trie_node *create_trie_node(void) {
	struct trie_node *node = malloc(sizeof(struct trie_node));
	DIE(!node, "malloc trie_node");
	node->left = NULL;
	node->right = NULL;
	node->route = NULL;
	return node;
}

void trie_insert(struct trie_node *root, struct route_table_entry *entry) {
	struct trie_node *current = root;
	uint32_t prefix = entry->prefix;
	uint32_t mask = entry->mask;
	int prefix_len = 0;

	uint32_t p = ntohl(prefix);
	while (mask) {
		prefix_len += mask & 1;
		mask >>= 1;
	}

	for (int i = 0; i < prefix_len; i++) {
		int bit = (p & (1U << 31)) ? 1 : 0;
		if (bit == 0) {
			if (!current->left) {
				current->left = create_trie_node();
			}
			current = current->left;
		} else {
			if (!current->right) {
				current->right = create_trie_node();
			}
			current = current->right;
		}
		p <<= 1;
	}

	current->route = entry;
}

struct route_table_entry *trie_lookup(struct trie_node *root, uint32_t dest_ip) {
	struct trie_node *current = root;
	struct route_table_entry *best_route = NULL;
	dest_ip = ntohl(dest_ip);

	for (int i = 0; i < 32; i++) {
		int bit = (dest_ip & (1U << 31)) ? 1 : 0;
		if (bit == 0) {
			if (!current->left) {
				break;
			}
			current = current->left;
		} else {
			if (!current->right) {
				break;
			}
			current = current->right;
		}
		dest_ip <<= 1;
		if (current->route) {
			best_route = current->route;
		}
	}

	return best_route;
}

void trie_free(struct trie_node *root) {
	if (!root) return;
	trie_free(root->left);
	trie_free(root->right);
	free(root);
}

uint8_t *get_arp_entry(uint32_t ip, struct arp_table_entry *arp_table, int arp_table_size) {
	for (int i = 0; i < arp_table_size; i++) {
		if (arp_table[i].ip == ip) {
			return arp_table[i].mac;
		}
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	int rtable_size = read_rtable(argv[1], rtable);
	DIE(rtable_size < 0, "read_rtable");
	
	struct trie_node *trie_root = create_trie_node();
	
	for (int i = 0; i < rtable_size; i++) {
		trie_insert(trie_root, &rtable[i]);
	}
	
	struct arp_table_entry arp_table[MAX_ARP_SIZE];
	int arp_table_size = 0;

	// packets waiting for ARP replies
	queue packet_q = create_queue();

	// interfaces of the router
	uint32_t interfaces[ROUTER_NUM_INTERFACES];
	for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
		interfaces[i] = inet_addr(get_interface_ip(i));
	}

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
		uint16_t ether_type = ntohs(eth_hdr->ethr_type);

		if (ether_type == ETHERTYPE_IP) {
			// handle IP packets
			printf("received IP packet\n");
			struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

			// verify IP checksum
			uint16_t received_checksum = ntohs(ip_hdr->checksum);
			ip_hdr->checksum = 0;
			uint16_t calculated_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr));

			if (received_checksum != calculated_checksum) {
				printf("checksum mismatch %x, %x\n", received_checksum, calculated_checksum);
				continue;
			}

			// ceck if packet is for the router
			uint32_t dest_ip = ntohl(ip_hdr->dest_addr);
			char *my_ip = get_interface_ip(interface);
			uint32_t my_ip_addr = inet_addr(my_ip);

			if (dest_ip == ntohl(my_ip_addr)) {
				// handle ICMP Echo Request
				printf("received ICMP Echo Request\n");
				struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
				if (ip_hdr->proto == IPPROTO_ICMP && icmp_hdr->mtype == ICMP_ECHO_REQUEST) {
					memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
					get_interface_mac(interface, eth_hdr->ethr_shost);

					ip_hdr->dest_addr = ip_hdr->source_addr;
					ip_hdr->source_addr = my_ip_addr;
					ip_hdr->tot_len = htons(len - sizeof(struct ether_hdr));
					ip_hdr->proto = IPPROTO_ICMP;
					ip_hdr->ttl = DEFAULT_TTL;
					ip_hdr->checksum = 0;
					ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

					icmp_hdr->mtype = ICMP_ECHO_REPLY;
					icmp_hdr->mcode = 0;
					icmp_hdr->check = 0;
					icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr)));

					send_to_link(len, buf, interface);
					continue;
				}
				continue;
			}

			// check TTL
			if (ip_hdr->ttl <= 1) {
				printf("TTL expired\n");
				char icmp_buf[MAX_PACKET_LEN];
				struct ether_hdr *icmp_eth_hdr = (struct ether_hdr *)icmp_buf;
				struct ip_hdr *icmp_ip_hdr = (struct ip_hdr *)(icmp_buf + sizeof(struct ether_hdr));
				struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(icmp_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

				memcpy(icmp_eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
				get_interface_mac(interface, icmp_eth_hdr->ethr_shost);
				icmp_eth_hdr->ethr_type = htons(ETHERTYPE_IP);

				memcpy(icmp_ip_hdr, ip_hdr, sizeof(struct ip_hdr));
				icmp_ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + ICMP_HDR_CPY_LEN);
				icmp_ip_hdr->proto = IPPROTO_ICMP;
				icmp_ip_hdr->ttl = DEFAULT_TTL;
				icmp_ip_hdr->source_addr = my_ip_addr;
				icmp_ip_hdr->dest_addr = ip_hdr->source_addr;
				icmp_ip_hdr->checksum = 0;
				icmp_ip_hdr->checksum = htons(checksum((uint16_t *)icmp_ip_hdr, sizeof(struct ip_hdr)));

				icmp_hdr->mtype = ICMP_TIME_EXCEEDED;
				icmp_hdr->mcode = 0;
				icmp_hdr->check = 0;
				memcpy(icmp_hdr + 1, ip_hdr, ICMP_HDR_CPY_LEN);
				icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmp_hdr) + ICMP_HDR_CPY_LEN));

				send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + ICMP_HDR_CPY_LEN, icmp_buf, interface);
				continue;
			}

			// decrement TTL, update checksum
			ip_hdr->ttl--;
			ip_hdr->checksum = 0;
			ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

			struct route_table_entry *best_route = trie_lookup(trie_root, ip_hdr->dest_addr);

			if (best_route == NULL) {
				printf("no route found for %s\n", inet_ntoa(*(struct in_addr *)&ip_hdr->dest_addr));
				char icmp_buf[MAX_PACKET_LEN];
				struct ether_hdr *icmp_eth_hdr = (struct ether_hdr *)icmp_buf;
				struct ip_hdr *icmp_ip_hdr = (struct ip_hdr *)(icmp_buf + sizeof(struct ether_hdr));
				struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(icmp_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

				memcpy(icmp_eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
				get_interface_mac(interface, icmp_eth_hdr->ethr_shost);
				icmp_eth_hdr->ethr_type = htons(ETHERTYPE_IP);

				memcpy(icmp_ip_hdr, ip_hdr, sizeof(struct ip_hdr));
				icmp_ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + ICMP_HDR_CPY_LEN);
				icmp_ip_hdr->proto = IPPROTO_ICMP;
				icmp_ip_hdr->ttl = DEFAULT_TTL;
				icmp_ip_hdr->source_addr = my_ip_addr;
				icmp_ip_hdr->dest_addr = ip_hdr->source_addr;
				icmp_ip_hdr->checksum = 0;
				icmp_ip_hdr->checksum = htons(checksum((uint16_t *)icmp_ip_hdr, sizeof(struct ip_hdr)));

				icmp_hdr->mtype = ICMP_DEST_UNREACH;
				icmp_hdr->mcode = 0;
				icmp_hdr->check = 0;
				memcpy(icmp_hdr + 1, ip_hdr, ICMP_HDR_CPY_LEN);
				icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmp_hdr) + ICMP_HDR_CPY_LEN));

				send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + ICMP_HDR_CPY_LEN, icmp_buf, interface);
				continue;
			}

			// check ARP table for next hop MAC
			uint8_t *next_hop_mac = get_arp_entry(best_route->next_hop, arp_table, arp_table_size);
			if (!next_hop_mac) {
				printf("no ARP entry for %s\n", inet_ntoa(*(struct in_addr *)&best_route->next_hop));
				// send ARP request
				char arp_buf[sizeof(struct ether_hdr) + sizeof(struct arp_hdr)];
				struct ether_hdr *arp_eth_hdr = (struct ether_hdr *)arp_buf;
				struct arp_hdr *arp_hdr = (struct arp_hdr *)(arp_buf + sizeof(struct ether_hdr));

				arp_eth_hdr->ethr_type = htons(ETHERTYPE_ARP);
				memset(arp_eth_hdr->ethr_dhost, 0xff, 6);
				get_interface_mac(best_route->interface, arp_eth_hdr->ethr_shost);

				arp_hdr->hw_type = htons(ETHER_HW_TYPE);
				arp_hdr->proto_type = htons(ETHERTYPE_IP);
				arp_hdr->opcode = htons(ARP_REQUEST);
				arp_hdr->hw_len = 6;
				arp_hdr->proto_len = 4;
				memcpy(arp_hdr->shwa, arp_eth_hdr->ethr_shost, 6);
				memset(arp_hdr->thwa, 0, 6);
				arp_hdr->sprotoa = interfaces[best_route->interface];
				arp_hdr->tprotoa = best_route->next_hop;

				send_to_link(sizeof(arp_buf), arp_buf, best_route->interface);

				// enqueue packet
				struct queued_packet *qp = malloc(sizeof(struct queued_packet));
				qp->packet = malloc(len);
				memcpy(qp->packet, buf, len);
				qp->len = len;
				queue_enq(packet_q, qp);
				continue;
			}

			// update ethernet header and forward
			get_interface_mac(best_route->interface, eth_hdr->ethr_shost);
			memcpy(eth_hdr->ethr_dhost, next_hop_mac, 6);
			send_to_link(len, buf, best_route->interface);
		} else if (ether_type == ETHERTYPE_ARP) {
			// handle ARP packets
			struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
			uint16_t opcode = ntohs(arp_hdr->opcode);

			if (opcode == ARP_REQUEST) {
				// check if the request is for this router
				if (arp_hdr->tprotoa == interfaces[interface]) {
					// Send ARP reply
					memcpy(eth_hdr->ethr_dhost, arp_hdr->shwa, 6);
					get_interface_mac(interface, eth_hdr->ethr_shost);
					eth_hdr->ethr_type = htons(ETHERTYPE_ARP);

					arp_hdr->hw_type = htons(ETHER_HW_TYPE);
					arp_hdr->proto_type = htons(ETHERTYPE_IP);
					arp_hdr->opcode = htons(ARP_REPLY);
					arp_hdr->hw_len = 6;
					arp_hdr->proto_len = 4;
					memcpy(arp_hdr->thwa, arp_hdr->shwa, 6);
					get_interface_mac(interface, arp_hdr->shwa);
					arp_hdr->tprotoa = arp_hdr->sprotoa;
					arp_hdr->sprotoa = interfaces[interface];

					send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), buf, interface);
				}
			} else if (opcode == ARP_REPLY) {
				uint8_t *prev_mac = get_arp_entry(arp_hdr->sprotoa, arp_table, arp_table_size);
				if (!prev_mac) {
					if (arp_table_size < MAX_ARP_SIZE) {
						arp_table[arp_table_size].ip = arp_hdr->sprotoa;
						memcpy(arp_table[arp_table_size].mac, arp_hdr->shwa, 6);
						arp_table_size++;
					} else {
						printf("ARP table full\n");
					}
				} else {
					memcpy(prev_mac, arp_hdr->shwa, 6);
				}

				// process queued packets
				queue temp_q = create_queue();
				while (!queue_empty(packet_q)) {
					struct queued_packet *qp = (struct queued_packet *)queue_deq(packet_q);
					char *packet = qp->packet;
					size_t packet_len = qp->len;
					struct ether_hdr *packet_eth_hdr = (struct ether_hdr *)packet;
					struct ip_hdr *packet_ip_hdr = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));

					struct route_table_entry *route = trie_lookup(trie_root, packet_ip_hdr->dest_addr);
					if (!route) {
						free(packet);
						free(qp);
						continue;
					}

					uint8_t *mac = get_arp_entry(route->next_hop, arp_table, arp_table_size);
					if (!mac) {
						queue_enq(temp_q, qp);
						continue;
					}

					get_interface_mac(route->interface, packet_eth_hdr->ethr_shost);
					memcpy(packet_eth_hdr->ethr_dhost, mac, 6);
					send_to_link(packet_len, packet, route->interface);
					free(packet);
					free(qp);
				}
				while (!queue_empty(temp_q)) {
					queue_enq(packet_q, queue_deq(temp_q));
				}
				free(temp_q);
			}
		} else {
			// ignore other packet types
			printf("unknown ether type %x\n", ether_type);
			continue;
		}
	}

	trie_free(trie_root);
	return 0;
}