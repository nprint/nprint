/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "udp_header.hpp"

void *UDPHeader::get_raw() {
    return (void *)raw;
}

void UDPHeader::set_raw(void *raw) {
    this->raw = (struct udphdr *)raw;
}

void UDPHeader::print_header(FILE *out) {
    if (raw == NULL) {
        fprintf(out, "UDPHeader: raw data not set\n");
        return;
    }

    fprintf(out, "UDP header: srcprt: %u, dstprt: %u, len: %u, cksum: %u\n",
           ntohs(raw->uh_sport), ntohs(raw->uh_dport), ntohs(raw->uh_ulen),
           ntohs(raw->uh_sum));
}

uint32_t UDPHeader::get_header_len() {
    return 8;
}

void UDPHeader::get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with) {
    make_bitstring(SIZE_UDP_HEADER_BITSTRING, raw, to_fill, fill_with);
}

void UDPHeader::get_bitstring_header(std::vector<std::string> &to_fill) {
    std::vector<std::tuple<std::string, uint32_t>> v;
    v.push_back(std::make_tuple("udp_sport", 16));
    v.push_back(std::make_tuple("udp_dport", 16));
    v.push_back(std::make_tuple("udp_len", 16));
    v.push_back(std::make_tuple("udp_cksum", 16));

    PacketHeader::make_bitstring_header(v, to_fill);
}

std::string UDPHeader::get_port(bool src) {
    if (raw == NULL) {
        return "NULL";
    } else if (src) {
        return std::to_string(ntohs(raw->uh_sport));
    } else {
        return std::to_string(ntohs(raw->uh_dport));
    }
}

uint16_t UDPHeader::get_sport() {
    return (raw != NULL) ? ntohs(raw->uh_sport) : 0;
}

uint16_t UDPHeader::get_dport() {
    return (raw != NULL) ? ntohs(raw->uh_dport) : 0;
}
