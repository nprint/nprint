/*
 * Copyright 2024 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "dns_header.hpp"

void *DNSHeader::get_raw() {
    return (void *)raw;
}

void DNSHeader::set_raw(void *raw) {
    this->raw = (struct dns_header *)raw;
}

void DNSHeader::print_header(FILE *out) {
    if (raw == NULL) {
        fprintf(out, "DNSHeader: raw data not set\n");
        return;
    }
    fprintf(out, "DNSHeader: id: %d, flags: %d, qdcount: %d, ancount: %d, nscount: %d, arcount: %d\n", 
           ntohs(raw->id), ntohs(raw->flags), ntohs(raw->qdcount), ntohs(raw->ancount), ntohs(raw->nscount), ntohs(raw->arcount));
}

uint32_t DNSHeader::get_header_len() {
    return sizeof(struct dns_header); // Fixed 12 byte header
}

void DNSHeader::get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with) {
    if (raw == NULL) {
        make_bitstring(SIZE_DNS_HEADER_BITSTRING, NULL, to_fill, fill_with);
        return;
    }
    make_bitstring(SIZE_DNS_HEADER_BITSTRING, (void *)raw, to_fill, fill_with);
}

void DNSHeader::get_bitstring_header(std::vector<std::string> &to_fill) {
    std::vector<std::tuple<std::string, uint32_t>> v;
    v.push_back(std::make_tuple("dns_id", 16));
    v.push_back(std::make_tuple("dns_flags", 16));
    v.push_back(std::make_tuple("dns_qdcount", 16));
    v.push_back(std::make_tuple("dns_ancount", 16));
    v.push_back(std::make_tuple("dns_nscount", 16));
    v.push_back(std::make_tuple("dns_arcount", 16));

    PacketHeader::make_bitstring_header(v, to_fill);
}