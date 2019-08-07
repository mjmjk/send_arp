#include "socket.h"


//ifreq = interface request
int get_my_addr(pcap_arg *arg, char *dev)
{
    int sock;
    struct ifreq ifr;
    struct addrinfo ai, *ai_ret;
    int rc_gai;

    memset(&ai, 0, sizeof(ai));
    ai.ai_family = AF_INET;
    ai.ai_socktype = SOCK_DGRAM;
    ai.ai_flags = AI_ADDRCONFIG;

    if((rc_gai = getaddrinfo(nullptr, "0", &ai, &ai_ret)) != 0)
    {
        printf("erro get addrinfo: %s", (rc_gai));
        return RET_ERROR;
    }

    sock = socket(ai_ret->ai_family, ai_ret->ai_socktype, ai_ret->ai_protocol);

    if(sock == -1)
    {
        printf("error socket!!");
        return RET_ERROR;

    }

    strncpy(ifr.ifr_ifrn.ifrn_name, dev,IFNAMSIZ -1);

    // get mac address
    if(ioctl(sock, SIOCGIFHWADDR, &ifr) == -1)
    {
        printf("error ioctl!!Not get Mac Address");
        return RET_ERROR;
    }

    memcpy(arg->mac_address, ifr.ifr_ifru.ifru_hwaddr.sa_data,MAC_ADDRESS_LEN);


    //get ip address
    if(ioctl(sock, SIOCGIFADDR, &ifr) == -1)
    {
            printf("error ioctl!! Not get IP Address");
            return RET_ERROR;
    }

    memcpy(&(arg->local_ip), &(((struct sockaddr_in *)&ifr.ifr_ifru.ifru_addr)->sin_addr),sizeof (struct in_addr));



    close(sock);

    return RET_SUCCESS;
}






