/*
  * Copyright 2020 nPrint
  * Licensed under the Apache License, Version 2.0 (the "License"); you may not
  * use this file except in compliance with the License. You may obtain a copy
  * of the License at https://www.apache.org/licenses/LICENSE-2.0
*/

#include "payload.hpp"

void *Payload::get_raw() { return raw; }

void Payload::set_raw(void * raw) { this->raw = raw; }

void Payload::print_header()
{
    printf("Payload: length: %d\n", n_bytes);
}
uint32_t Payload::get_header_len() { return n_bytes; }

void Payload::get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with)
{
    int32_t zero_byte_width;
    zero_byte_width = max_payload_len - n_bytes;
    /* If no payload fill with max payload bytes */
    if(n_bytes == 0)
    {
        make_bitstring(max_payload_len, NULL, to_fill, fill_with);
    }
    /* If payload but payload is smaller than maximum payload length */
    else if(zero_byte_width > 0)
    {
        make_bitstring(n_bytes, raw, to_fill, fill_with);
        make_bitstring(zero_byte_width, NULL, to_fill, fill_with);
    }
    /* Payload is larger or as large as maximum payload length, */
    else
    {
        make_bitstring(max_payload_len, raw, to_fill, fill_with);
    }
}

void Payload::get_bitstring_header(std::vector<std::string> &to_fill)
{
    std::vector<std::tuple<std::string, uint32_t> > v;

    if(max_payload_len == 0) return;

    v.push_back(std::make_tuple("payload", max_payload_len * 8));
    PacketHeader::make_bitstring_header(v, to_fill);
}


/* Specific to Payload */

void Payload::set_info(uint32_t n_bytes, uint32_t max_payload_len)
{
    this->n_bytes = n_bytes;
    this->max_payload_len = max_payload_len;
}

