/*
 * Copyright nPrint 2021
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "radiotap_header.hpp"

void *RadiotapHeader::get_raw() {
    return (void *) raw;
}

void RadiotapHeader::set_raw(void *raw) {
    this->raw = (struct radiotap_header *) raw;
}

void RadiotapHeader::print_header(FILE *out) {
    if (raw == NULL) {
        fprintf(out, "RadiotapHeader: raw data not set\n");
    } else {
        fprintf(out, "RadiotapHeader: %d bytes\n", get_header_len());
    }
}

uint32_t RadiotapHeader::get_header_len() {
    return SIZE_RADIOTAP_HEADER_BITSTRING;
}

void RadiotapHeader::get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with) {
    make_bitstring(SIZE_RADIOTAP_HEADER_BITSTRING, raw, to_fill, fill_with);
}

void RadiotapHeader::get_bitstring_header(std::vector<std::string> &to_fill) {
    std::vector<std::tuple<std::string, uint32_t> > v;

    v.push_back(std::make_tuple("radiotap_reversion", 1 * 8));
    v.push_back(std::make_tuple("radiotap_pad0", 1 * 8));
    v.push_back(std::make_tuple("radiotap_len", 2 * 8));
    v.push_back(std::make_tuple("radiotap_present", 12 * 8));
    v.push_back(std::make_tuple("radiotap_mactimestamp", 8 * 8));
    v.push_back(std::make_tuple("radiotap_flags", 1 * 8));
    v.push_back(std::make_tuple("radiotap_rate", 1 * 8));
    v.push_back(std::make_tuple("radiotap_channel", 2 * 8));
    v.push_back(std::make_tuple("radiotap_channelflags", 2 * 8));
    v.push_back(std::make_tuple("radiotap_antennasignal", 1 * 8));
    v.push_back(std::make_tuple("radiotap_pad1", 1 * 8));
    v.push_back(std::make_tuple("radiotap_rxflags", 2 * 8));
    v.push_back(std::make_tuple("radiotap_pad2", 6 * 8));
    v.push_back(std::make_tuple("radiotap_timestamp", 12 * 8));
    v.push_back(std::make_tuple("radiotap_antennas", 4 * 8));

    PacketHeader::make_bitstring_header(v, to_fill);
}
