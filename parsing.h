#ifndef PARSING_H
#define PARSING_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include "header.h"

//parsing ethernet header
int parsing_ethernet(const u_char *frame);

//parsing arp header
int parsing_arp(const u_char *packet, struct arp_header *ahdr);

#endif // PARSING_H
