#ifndef ALL_PCAP_H
#define ALL_PCAP_H

#define RECV_ITER_N 5

#include <pcap/pcap.h>
#include "pcap_msg.h"
#include "parsing.h"
#include "header.h"


//open pcap handler
int init_handle(pcap_arg *arg,char *dev);

//set handle arp
int set_handle_arp(pcap_arg *arg);

//close pcap handler
int close_handle(pcap_arg *arg);

//send arp request
int send_arp_request(pcap_arg *arg, char *addr_s);

//send arp reply
int send_arp_reply(pcap_arg *arg, struct arp_header *ahdr, char *addr_t);


//send arp packet
int send_arp_packet(pcap_arg *arg, struct ether_header *ehdr, struct arp_header *ahdr);



//received arp packet
int recv_arp_packet(pcap_arg *arg, struct arp_header *ahdr);

#endif // ALL_PCAP_H
