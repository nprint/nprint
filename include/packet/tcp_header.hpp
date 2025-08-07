/*
 * Copyright nPrint 2020
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef TCP_HEADER
#define TCP_HEADER

#include <netinet/tcp.h>

#include "packet_header.hpp"

#define SIZE_TCP_HEADER_BITSTRING 60

class TCPHeader : public PacketHeader {
  public:
    /* Required Functions */
    void *get_raw();
    void set_raw(void *raw);
    void print_header(FILE *out);
    uint32_t get_header_len();
    std::string get_port(bool src);
    uint16_t get_sport();
    uint16_t get_dport();
    void get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with);
    void get_bitstring_header(std::vector<std::string> &to_fill);

    /* Header Specific */
  private:
    struct tcphdr *raw = NULL;
};

#endif
