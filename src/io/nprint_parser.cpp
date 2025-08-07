/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "nprint_parser.hpp"

#define NFILE_IP_LOC 0

void NprintParser::process_file() {
    pcap_t *pd;
    pcap_dumper_t *t;
    std::string line, pkt;
    std::vector<std::string> tokens;
    std::ifstream instream(config.infile);
    std::tuple<void *, uint64_t> packet_info;
    std::string bits;
    struct timeval *time;
    pcap_pkthdr *pcap_header;

    time = new timeval;
    time->tv_sec = 0;
    time->tv_usec = 0;
    pcap_header = new pcap_pkthdr;

    if (config.eth) {
        pd = pcap_open_dead(DLT_EN10MB, 65535 /* snaplen */);
    } else {
        pd = pcap_open_dead(DLT_RAW, 65535 /* snaplen */);
    }

    t = pcap_dump_open(pd, config.outfile);
    /*  header */
    getline(instream, line);
    while (getline(instream, line)) {
        bits = clean_line(line);
        packet_info = parse_packet(bits);
        if (std::get<0>(packet_info) != NULL) {
            pcap_header->caplen = std::get<1>(packet_info);
            pcap_header->len = std::get<1>(packet_info);
            pcap_dump((u_char *)t, pcap_header,
                      (u_char *)std::get<0>(packet_info));
        }
    }
}

std::string NprintParser::clean_line(std::string &line) {
    uint64_t i;
    bool first_column, neg;
    std::string packet_bits;

    first_column = true;
    neg = false;
    for (i = 0; i < line.length(); i++) {
        if (line[i] == ',' && first_column == true)
            first_column = false;
        if (line[i] == '-')
            neg = true;
        if ((line[i] == '0' || line[i] == '1') && first_column == false) {
            if (neg == true) {
                neg = false;
            } else {
                packet_bits.push_back(line[i]);
            }
        }
    }
    return packet_bits;
}

std::tuple<void *, uint64_t> NprintParser::parse_packet(std::string &bits) {
    struct ip *v4;
    struct ether_header *eth;
    struct ip6_hdr *v6;
    u_int8_t *packet;
    uint32_t len;

    packet = transform_bitstring(bits);

    len = 0;
    if (config.eth) {
        eth = (struct ether_header *)packet;
        v4 = (struct ip *)&eth[1];
    } else {
        v4 = (struct ip *)packet;
    }
    if (v4->ip_v == 4) {
        len = ntohs(v4->ip_len);
        if (config.eth)
            len += 14;
    } else if (v4->ip_v == 6) {
        printf("v6\n");
        v6 = (struct ip6_hdr *)packet;
        /* fixed header, change when full ipv6 implemented */
        len = ntohs(v6->ip6_plen) + 40;
        if (config.eth)
            len += 14;
    } else {
        packet = NULL;
    }

    return std::make_tuple((void *)packet, len);
}

uint8_t *NprintParser::transform_bitstring(std::string &bits) {
    uint64_t i, j;
    uint8_t *h;

    j = 7;
    h = new uint8_t[bits.length() / 8];
    memset(h, 0, bits.length() / 8);
    for (i = 0; i < bits.length(); i++) {
        h[i / 8] |= (bits[i] - 48) << j;
        j = (j - 1) % 8;
    }

    return h;
}

void NprintParser::format_and_write_header() {
    return;
}
