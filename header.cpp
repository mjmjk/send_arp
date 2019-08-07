#include "header.h"

void build_ether(u_char *frame, struct ether_header *hdr)
{
    memcpy(frame, hdr, ETH_HEADER_LEN);
}

void build_arp(u_char *packet, struct arp_header *hdr)
{
    hdr->htype = htons(0x01);
    hdr->ptype = htons(ETHERTYPE_IP); // ETHERTYPE_IP = 0X0800
    hdr->hlen = HWADDR_LEN;
    hdr->plen = PTADDR_LEN;
    memcpy(packet, hdr, ARP_HEADER_LEN);

}
