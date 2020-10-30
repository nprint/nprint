/*
  * Copyright 2020 nPrint
  * Licensed under the Apache License, Version 2.0 (the "License"); you may not
  * use this file except in compliance with the License. You may obtain a copy
  * of the License at https://www.apache.org/licenses/LICENSE-2.0
*/

#include "tcp_header.hpp"

void *TCPHeader::get_raw() { return (void *) raw; }

void TCPHeader::set_raw(void *raw) { this->raw = (struct tcphdr *) raw; }

void TCPHeader::print_header()
{
    if(raw == NULL)
    {
        printf("TCPHeader: raw data not set\n");
        return;
    }
    printf("TCPHeader: src_prt: %d, dst_prt: %d\n", ntohs(raw->th_sport),
                                                    ntohs(raw->th_dport));
}

uint32_t TCPHeader::get_header_len() { return raw->th_off * 4; }

void TCPHeader::get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with)
{
    uint32_t tcp_header_byte_size, zero_byte_width;

    if(raw == NULL)
    {
        make_bitstring(SIZE_TCP_HEADER_BITSTRING, NULL, to_fill, fill_with);
        return;
    }
    tcp_header_byte_size = raw->th_off * 4;
    zero_byte_width = SIZE_TCP_HEADER_BITSTRING - tcp_header_byte_size;
    make_bitstring(tcp_header_byte_size, (void *) raw, to_fill, fill_with);
    make_bitstring(zero_byte_width, NULL, to_fill, fill_with);
}

void TCPHeader::get_bitstring_header(std::vector<std::string> &to_fill)
{
    std::vector<std::tuple<std::string, uint32_t> > v;
    v.push_back(std::make_tuple("tcp_sprt", 16));  v.push_back(std::make_tuple("tcp_dprt", 16));
    v.push_back(std::make_tuple("tcp_seq", 32));  v.push_back(std::make_tuple("tcp_ackn", 32));
    v.push_back(std::make_tuple("tcp_doff", 4));  v.push_back(std::make_tuple("tcp_res", 3));
    v.push_back(std::make_tuple("tcp_ns", 1));  v.push_back(std::make_tuple("tcp_cwr", 1));
    v.push_back(std::make_tuple("tcp_ece", 1));  v.push_back(std::make_tuple("tcp_urg", 1));
    v.push_back(std::make_tuple("tcp_ackf", 1));  v.push_back(std::make_tuple("tcp_psh", 1));
    v.push_back(std::make_tuple("tcp_rst", 1));  v.push_back(std::make_tuple("tcp_syn", 1));
    v.push_back(std::make_tuple("tcp_fin", 1));  v.push_back(std::make_tuple("tcp_wsize", 16));
    v.push_back(std::make_tuple("tcp_cksum", 16));  v.push_back(std::make_tuple("tcp_urp", 16));
    v.push_back(std::make_tuple("tcp_opt", 320));

    PacketHeader::make_bitstring_header(v, to_fill);
}

std::string TCPHeader::get_port(bool src)
{
    if(raw == NULL)
    {
        return "NULL";
    }
    else if(src)
    {
        return std::to_string(raw->th_sport);
    }
    else
    {
       return std::to_string(raw->th_dport); 
    }
}
