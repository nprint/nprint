/*
 * Copyright nPrint 2021
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef RADIOTAP_HEADER
#define RADIOTAP_HEADER

#include "packet_header.hpp"

#define SIZE_RADIOTAP_HEADER_BITSTRING 56

struct radiotap_header {
    uint8_t* radiotap_data;	/* all bytes for radiotap_data 	*/
};

class RadiotapHeader : public PacketHeader {
    public:
        /* Required Functions */
        void* get_raw();
        void set_raw(void *raw);
        void print_header(FILE *out);
        uint32_t get_header_len();
        void get_bitstring(std::vector<int8_t>  &to_fill, int8_t fill_with);
        void get_bitstring_header(std::vector<std::string> &to_fill);
    private:
        struct radiotap_header* raw = NULL;
};

#endif
