# Software Router (C)

This project implements a functional router in C, meeting the requirements for IPv4 routing, Longest Prefix Match (LPM), and the ARP and ICMP protocols.

## Features

### 1. IPv4 Routing

- Receives and validates IP packets (verifies checksum and TTL).
- Decrements the TTL, recalculates the checksum, and forwards packets.
- Sends an ICMP *Time Exceeded* message when `TTL <= 1`.
- Updates the MAC addresses in the Ethernet header.
- Does not rely on a static ARP table.

### 2. Efficient Longest Prefix Match

- Uses a binary trie for LPM instead of a linear search.
- Provides fast lookups (O(32) vs. O(n)) for large tables (up to 80,000 entries).
- Includes dedicated trie insertion and lookup functions.

### 3. ARP Protocol

- Processes ARP requests and replies dynamically.
- Populates the ARP table (up to 1,000 entries) without a static file.
- Stores resolved MAC addresses persistently.
- Queues packets when a MAC address is unknown and sends them once the corresponding ARP reply arrives.

### 4. ICMP Protocol

- Replies to ICMP *Echo Request* with *Echo Reply*.
- Generates ICMP *Time Exceeded* when the TTL expires.
- Generates ICMP *Destination Unreachable* when no route exists.

## How it works

To successfully route a ping from `h1` to `h2`, the router implements the IPv4 forwarding process using a routing table. Resolving the physical (MAC) addresses through the ARP protocol is also required in order to forward data to the next hop in the topology. Along the way, the router modifies each packet by decrementing the TTL and recalculating the checksum in the IP header.
