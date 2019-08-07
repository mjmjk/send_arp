#ifndef HEADER_H
#define HEADER_H

#include "pcap_msg.h"

#define ETH_HEADER_LEN    14

#define ARP_HEADER_LEN  28



#define ARP_REQUEST 0x01

#define ARP_REPLY   0x02

struct arp_header {

    u_int16_t htype;    // Hardware Type: common 1

    u_int16_t ptype;    // Protocol Type: ipv4 = 0x0800

    u_char hlen;        // Hardware Address Length = 6

    u_char plen;        // Protocol Address Length = 4

    u_int16_t op;       // Operation Code = 1: arp Request 2: arp Reply 3:RARP request 4: RARP Reply

    u_char sha[HWADDR_LEN];      // Sender Hardware Address

    u_char spa[PTADDR_LEN];      // Sender Protocol Address

    u_char tha[HWADDR_LEN];      // Target Hardware Address

    u_char tpa[PTADDR_LEN];      // Target Protocol Address

};

void build_ether(u_char *frame, struct ether_header *hdr);

void build_arp(u_char *packet, struct arp_header *hdr);

#endif // HEADER_H
