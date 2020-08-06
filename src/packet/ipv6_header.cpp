/*
  * Copyright 2020 nPrint
  * Licensed under the Apache License, Version 2.0 (the "License"); you may not
  * use this file except in compliance with the License. You may obtain a copy
  * of the License at https://www.apache.org/licenses/LICENSE-2.0
*/

#include "ipv6_header.hpp"

void *IPv6Header::get_raw() { return (void *) raw; }

void IPv6Header::set_raw(void *raw) { this->raw = (struct ip6_hdr *) raw; }

void IPv6Header::print_header()
{

}

uint32_t IPv6Header::get_header_len() { return 40; }

std::string IPv6Header::get_src_ip()
{
    char s[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, (void *) &raw->ip6_src, s, INET6_ADDRSTRLEN);

    return std::string(s);
}

std::string IPv6Header::get_dst_ip()
{
    char s[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, (void *) &raw->ip6_dst, s, INET6_ADDRSTRLEN);
    
    return std::string(s);
}

void IPv6Header::get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with)
{
    if(raw == NULL)
    {
        make_bitstring(SIZE_IPV6_HEADER_BITSTRING, NULL, to_fill, fill_with);
        return;
    }
    
    make_bitstring(SIZE_IPV6_HEADER_BITSTRING, (void *) raw, to_fill, fill_with);
}

void IPv6Header::get_bitstring_header(std::vector<std::string> &to_fill)
{
    std::vector<std::tuple<std::string, uint32_t> > v;
    v.push_back(std::make_tuple("ipv6_ver", 4)); 
    v.push_back(std::make_tuple("ipv6_tc", 8)); 
    v.push_back(std::make_tuple("ipv6_fl", 20)); 
    v.push_back(std::make_tuple("ipv6_len", 16)); 
    v.push_back(std::make_tuple("ipv6_nh", 8)); 
    v.push_back(std::make_tuple("ipv6_hl", 8)); 
    v.push_back(std::make_tuple("ipv6_src", 128)); 
    v.push_back(std::make_tuple("ipv6_dst", 128)); 

    PacketHeader::make_bitstring_header(v, to_fill);
}

/* Header Specific */
uint8_t  IPv6Header::get_ip_proto()  { return raw->ip6_nxt; }
uint32_t IPv6Header::get_total_len() { return ntohs(raw->ip6_plen) + 40; } 
