/*
  * Copyright 2020 nPrint
  * Licensed under the Apache License, Version 2.0 (the "License"); you may not
  * use this file except in compliance with the License. You may obtain a copy
  * of the License at https://www.apache.org/licenses/LICENSE-2.0
*/

#include "ipv4_header.hpp"

void *IPv4Header::get_raw() { return (void *) raw; }

void IPv4Header::set_raw(void *raw) { this->raw = (struct ip*) raw; }

void IPv4Header::print_header()
{
    if(raw == NULL)
    {
        printf("IPv4Header: raw data not set\n");
    }
    else
    {
        printf("IPv4Header: src_ip: %s, dst_ip: %s\n", inet_ntoa(raw->ip_src), inet_ntoa(raw->ip_dst));
    }
}

uint32_t IPv4Header::get_header_len() { return raw->ip_hl * 4; }

void IPv4Header::get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with)
{
    uint32_t ip_header_byte_size, zero_byte_width;

    if(raw == NULL)
    {
        make_bitstring(SIZE_IPV4_HEADER_BITSTRING, NULL, to_fill, fill_with);
        return;
    }

    ip_header_byte_size = raw->ip_hl * 4;
    zero_byte_width = SIZE_IPV4_HEADER_BITSTRING - ip_header_byte_size;

    make_bitstring(ip_header_byte_size, (void *) raw, to_fill, fill_with);
    make_bitstring(zero_byte_width, NULL, to_fill, fill_with);
}

void IPv4Header::get_bitstring_header(std::vector<std::string> &to_fill)
{
    std::vector<std::tuple<std::string, uint32_t> > v;
    v.push_back(std::make_tuple("ipv4_ver", 4));  v.push_back(std::make_tuple("ipv4_hl", 4));
    v.push_back(std::make_tuple("ipv4_tos", 8));  v.push_back(std::make_tuple("ipv4_tl", 16));
    v.push_back(std::make_tuple("ipv4_id", 16));  v.push_back(std::make_tuple("ipv4_rbit", 1));
    v.push_back(std::make_tuple("ipv4_dfbit", 1));  v.push_back(std::make_tuple("ipv4_mfbit", 1));
    v.push_back(std::make_tuple("ipv4_foff", 13));  v.push_back(std::make_tuple("ipv4_ttl", 8));
    v.push_back(std::make_tuple("ipv4_proto", 8));  v.push_back(std::make_tuple("ipv4_cksum", 16));
    v.push_back(std::make_tuple("ipv4_src", 32));  v.push_back(std::make_tuple("ipv4_dst", 32));
    v.push_back(std::make_tuple("ipv4_opt", 320));
     
    PacketHeader::make_bitstring_header(v, to_fill);
}



/* Header Specific */

std::string IPv4Header::get_src_ip() { return std::string(inet_ntoa(raw->ip_src)); }
std::string IPv4Header::get_dst_ip() { return std::string(inet_ntoa(raw->ip_dst)); }
uint8_t IPv4Header::get_ip_proto()   { return raw->ip_p; }
uint16_t IPv4Header::get_total_len() { return ntohs(raw->ip_len); }
