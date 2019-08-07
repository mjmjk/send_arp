#include "header.h"


//save ethernet header information
void get_ethernet(u_char *frame, struct ether_header *ehdr)
{
    memcpy(frame, ehdr, ETH_HEADER_LEN);
}

//save arp header information
void get_arp(u_char *packet, struct arp_header *ahdr)
{
    ahdr->htype = htons(0x01);
    ahdr->ptype = htons(ETHERTYPE_IP); // ETHERTYPE_IP = 0X0800
    ahdr->hlen = MAC_ADDRESS_LEN;
    ahdr->plen = IP_ADDRESS_LEN;
    memcpy(packet, ahdr, ARP_HEADER_LEN);

}
