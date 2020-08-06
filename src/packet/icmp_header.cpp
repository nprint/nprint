/*
  * Copyright 2020 nPrint
  * Licensed under the Apache License, Version 2.0 (the "License"); you may not
  * use this file except in compliance with the License. You may obtain a copy
  * of the License at https://www.apache.org/licenses/LICENSE-2.0
*/

#include "icmp_header.hpp"

/* Required Functions */
void *ICMPHeader::get_raw() { return (void *) raw; }

void ICMPHeader::set_raw(void * raw) { this->raw = (struct icmp *) raw; }

void ICMPHeader::print_header()
{
    if(raw == NULL)
    {
        printf("ICMPHeader:: raw data not set\n");
    }
    else
    {
        printf("icmp: type: %u, code: %u\n", raw->icmp_type, raw->icmp_code);
    }
}

void ICMPHeader::get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with)
{
    if(raw == NULL)
    {
        make_bitstring(SIZE_ICMP_HEADER_BITSTRING, NULL, to_fill, fill_with);
        return;
    }
    make_bitstring(SIZE_ICMP_HEADER_BITSTRING, (void *) raw, to_fill, fill_with);
}

void ICMPHeader::get_bitstring_header(std::vector<std::string> &to_fill)
{
    std::vector<std::tuple<std::string, uint32_t> > v;
    v.push_back(std::make_tuple("icmp_type", 8));  v.push_back(std::make_tuple("icmp_code", 8));
    v.push_back(std::make_tuple("icmp_cksum", 16));  v.push_back(std::make_tuple("icmp_roh", 32));

    PacketHeader::make_bitstring_header(v, to_fill);
}
