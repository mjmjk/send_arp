#include "parsing.h"


//parsing ethernet header
int parsing_ethernet(const u_char *frame)
{
    struct ether_header *ethdr;

    ethdr = (struct ether_header *)frame;

    if(ntohs(ethdr->ether_type) == ETHERTYPE_ARP)
    {
        return TRUE;
    }
    else {
        return FALSE;
    }
}

//parsing arp header
int parsing_arp(const u_char *packet, struct arp_header *ahdr)
{
    memcpy(ahdr, packet, ARP_HEADER_LEN);
}
