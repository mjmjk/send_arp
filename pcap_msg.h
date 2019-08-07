#ifndef PCAP_MSG_H
#define PCAP_MSG_H
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



#define RET_SUC 0

#define RET_ERR 2



#define BUF_LEN 256

#define HWADDR_LEN  6

#define PTADDR_LEN  4

typedef struct pcap_arg

{

    pcap_arg *handle;
    pcap_t *hand;

    bpf_u_int32 mask;

    bpf_u_int32 net;

    u_char local_mac[HWADDR_LEN];

    struct in_addr local_ip;

    struct in_addr sender_ip;

} pcap_arg;

#define print_msg(io, msgtype, arg) \

/*
    flockfile(io); \

    fprintf(io, "["#msgtype"] [%s/%s:%03d] ", __FILE__, __FUNCTION__, __LINE__); \

    fprintf(io, arg); \

    fputc('\n', io); \

    funlockfile(io)
*/


#define print_msg_no_enter(io, msgtype, arg...) \
/*
    flockfile(io); \

    printf(io, "["#msgtype"] [%s/%s:%03d] ", __FILE__, __FUNCTION__, __LINE__); \

    fprintf(io, arg); \

    funlockfile(io);

*/

#define pr_err(arg) print_msg(stderr, ERR, arg)

#define pr_out(arg) print_msg(stdout, REP, arg)

#define pr_out_n(arg) print_msg_no_enter(stdout, REP, arg)



// dump function for debug

void dumpcode(const u_char *buf, int len);


#endif // PCAP_MSG_H
