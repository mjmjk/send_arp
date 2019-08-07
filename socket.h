#ifndef SOCKET_H
#define SOCKET_H

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "pcap_msg.h"


int get_my_addr(pcap_arg *arg, char *dev);

#endif // SOCKET_H
