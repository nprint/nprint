/*
 * Copyright nPrint 2020
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef IPv6_HEADER
#define IPv6_HEADER

#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "packet_header.hpp"

#define SIZE_IPV6_HEADER_BITSTRING 40

/*
 * Currently only supported fixed (first) IPv6 Header parsing
 */

class IPv6Header : public PacketHeader {
  public:
    /* Required Functions */
    void *get_raw();
    void set_raw(void *raw);
    void print_header(FILE *out);
    uint32_t get_header_len();
    void get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with);
    void get_bitstring_header(std::vector<std::string> &to_fill);

    /* Header Specific */
    std::string get_src_ip();
    std::string get_dst_ip();
    uint8_t get_ip_proto();
    uint32_t get_total_len();

  private:
    struct ip6_hdr *raw = NULL;
};

#endif
