/*
 * Copyright nPrint 2021
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef WLAN_HEADER
#define WLAN_HEADER

#include "packet_header.hpp"

// TODO: we only parse the first 10 bytes at this time 
#define SIZE_WLAN_HEADER_BITSTRING 10

struct wlan_header {
    uint8_t  type;
    uint8_t  flag;
    uint16_t duration;
    uint8_t  rx_addr[6];
    uint8_t  tx_addr[6];
};

class WlanHeader : public PacketHeader {
    public:
        /* Required Functions */
        void* get_raw();
        void set_raw(void *raw);
        void print_header(FILE *out);
        uint32_t get_header_len();
        void get_bitstring(std::vector<int8_t>  &to_fill, int8_t fill_with);
        void get_bitstring_header(std::vector<std::string> &to_fill);

        std::string get_tx_mac();

    private:
        struct wlan_header* raw = NULL;
};

#endif
