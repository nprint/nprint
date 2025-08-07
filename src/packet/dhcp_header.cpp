/*
 * Copyright nPrint 2020
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "dhcp_header.hpp"

void *DHCPHeader::get_raw() {
    return (void *)raw;
}

void DHCPHeader::set_raw(void *raw) {
    this->raw = (struct dhcp_header *)raw;
}

void DHCPHeader::print_header(FILE *out) {
    if (raw == NULL) {
        fprintf(out, "DHCPHeader: raw data not set\n");
        return;
    }

    fprintf(out, "DHCPHeader: op: %u, htype: %u, hlen: %u, hops: %u, xid: %u, ciaddr: %u, yiaddr: %u\n",
        raw->op, raw->htype, raw->hlen, raw->hops, ntohl(raw->xid),
        ntohl(raw->ciaddr), ntohl(raw->yiaddr));
}

uint32_t DHCPHeader::get_header_len() {
    return sizeof(struct dhcp_header);
}

void DHCPHeader::get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with) {
    if (raw == NULL) {
        make_bitstring(SIZE_DHCP_HEADER_BITSTRING, NULL, to_fill, fill_with);
        return;
    }
    make_bitstring(SIZE_DHCP_HEADER_BITSTRING, (void *)raw, to_fill, fill_with);
}

void DHCPHeader::get_bitstring_header(std::vector<std::string> &to_fill) {
    std::vector<std::tuple<std::string, uint32_t>> v;
    v.push_back({"dhcp_op", 8});
    v.push_back({"dhcp_htype", 8});
    v.push_back({"dhcp_hlen", 8});
    v.push_back({"dhcp_hops", 8});
    v.push_back({"dhcp_xid", 32});
    v.push_back({"dhcp_secs", 16});
    v.push_back({"dhcp_flags", 16});
    v.push_back({"dhcp_ciaddr", 32});
    v.push_back({"dhcp_yiaddr", 32});
    v.push_back({"dhcp_siaddr", 32});
    v.push_back({"dhcp_giaddr", 32});
    v.push_back({"dhcp_chaddr", 128});  // 16 bytes
    PacketHeader::make_bitstring_header(v, to_fill);
}
