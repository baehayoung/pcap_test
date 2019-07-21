#ifndef MYNET_H
#define MYNET_H

#include<stdint.h>
#include<pcap.h>
#include<arpa/inet.h>

struct myEthernet{
    uint8_t dMac[6];
    uint8_t sMac[6];
    uint16_t etherType;
    uint8_t data[0];
};

struct myIP{
    unsigned char ver:4;
    unsigned char hl:4;
    unsigned char tos;
    uint16_t len;
    uint16_t id;
    unsigned char flagsx:1;
    unsigned char flagsd:1;
    unsigned char flagsm:1;
    uint8_t flagoffset;
    uint8_t ttl;
    uint8_t ip_p;
    uint16_t checksum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
    uint8_t data[0];
};


struct myTcphdr{
    uint16_t tcp_sPort;
    uint16_t tcp_dPort;
    uint32_t seq;
    uint32_t ack;
    unsigned char hl:4;
    unsigned char reserved:4;
    unsigned char code_bits:8;
    uint16_t win_size;
    uint16_t checksum;
    uint16_t urgent_p;
    uint8_t data[10];
};

#endif // MYNET_H
