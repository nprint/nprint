/*
 * Copyright nPrint 2020
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef SUPERPACKET
#define SUPERPACKET

#include <tuple>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "conf.hpp"
#include "radiotap_header.hpp"
#include "wlan_header.hpp"
#include "ethernet_header.hpp"
#include "icmp_header.hpp"
#include "ipv4_header.hpp"
#include "ipv6_header.hpp"
#include "payload.hpp"
#include "tcp_header.hpp"
#include "udp_header.hpp"

class SuperPacket {
  public:
    SuperPacket(void *pkt, uint32_t max_payload_len, uint32_t linktype);
    std::string get_port(bool src);
    std::string get_ip_address(bool src);
    std::string get_tx_mac_address();
    void print_packet(FILE *out);
    bool check_parseable() {
        return parseable;
    };
    std::tuple<uint8_t, uint8_t> get_packet_type();
    void get_bitstring(Config *c, std::vector<int8_t> &to_fill);
    std::string get_index(Config *c);

  private:
    bool process_v4(void *pkt);
    bool process_v6(void *pkt);

    bool parseable;
    uint32_t max_payload_len;
    RadiotapHeader radiotap_header;
    WlanHeader wlan_header;
    EthHeader ethernet_header;
    IPv4Header ipv4_header;
    IPv6Header ipv6_header;
    TCPHeader tcp_header;
    UDPHeader udp_header;
    ICMPHeader icmp_header;
    Payload payload;
};

#endif
