#include <iostream>
#include <pcap/pcap.h>
#include "pcap_msg.h"
#include "all_pcap.h"
#include "socket.h"
#include "header.h"


using namespace std;

int main(int argc, char *argv[])
{


    pcap_arg arg;
    struct arp_header ahdr;

    if(argc<4)
    {
        printf("error!");
        exit(EXIT_FAILURE);
    }

    if(init_handle(&arg, argv[1]))
    {
        exit(EXIT_FAILURE);
    }

    if(set_handle_arp(&arg))
    {
        exit(EXIT_FAILURE);
    }


    //get my MAC, IP
    if(get_my_addr(&arg,argv[1]))
    {
        exit(EXIT_FAILURE);
    }

    //send ARP REQUEST

    if(send_arp_request(&arg, argv[2]))
    {
        exit(EXIT_FAILURE);
    }

    if(recv_arp_packet(&arg, &ahdr))
    {
        exit(EXIT_FAILURE);
    }

    for (int i =0;i<3; i++)
    {
        if(send_arp_reply(&arg, &ahdr, argv[3]))
        {
            exit(EXIT_FAILURE);
        }
    }

    if(close_handle(&arg))
    {
        exit(EXIT_FAILURE);
    }

    return 0;


    return 0;
}
