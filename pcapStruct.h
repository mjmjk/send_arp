#ifndef PCAPSTRUCT_H
#define PCAPSTRUCT_H

#include <sys/types.h>

#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <unistd.h>

#include <ctype.h>

#include <pcap/pcap.h>

#include <netdb.h>

#include <errno.h>

#include <netinet/if_ether.h>

#define TRUE    1

#define FALSE   0



#define RET_SUCCESS 0

#define RET_ERROR 2



#define BUF_LEN 256

//HardWare Address Lengh = MAc Address
#define MAC_ADDRESS_LEN  6

//Protocol Address length = Ip Address
#define IP_ADDRESS_LEN  4


//get packet information
typedef struct pcap_arg
{

    pcap_t *hand;

    bpf_u_int32 mask;

    bpf_u_int32 net;

    u_char mac_address[MAC_ADDRESS_LEN];

    struct in_addr local_ip;

    struct in_addr sender_ip;

} pcap_arg;


#endif // PCAPSTRUCT_H
