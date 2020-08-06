/*
 * Copyright nPrint 2020
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef SUPERPACKET
#define SUPERPACKET

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* Included to skip ethernet headers if they exist on packets */
#include <netinet/if_ether.h>

#include "conf.hpp"
#include "ipv4_header.hpp"
#include "ipv6_header.hpp"
#include "udp_header.hpp"
#include "tcp_header.hpp"
#include "icmp_header.hpp"
#include "payload.hpp"

class SuperPacket
{
    public:
        SuperPacket(void *pkt, uint32_t max_payload_len);
        void print_packet();
        std::string get_ip_address();
        bool check_parseable() { return parseable; };
        void get_bitstring(Config *c, std::vector<int8_t> &to_fill);
    private:
        void process_v4(void *pkt);
        void process_v6(void *pkt);

        bool parseable;
        uint32_t max_payload_len;
        IPv4Header ipv4_header;
        IPv6Header ipv6_header;
        TCPHeader tcp_header;
        UDPHeader udp_header;
        ICMPHeader icmp_header;
        Payload payload;
};

#endif
