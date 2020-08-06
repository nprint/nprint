/*
 * Copyright nPrint 2020
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef PAYLOAD
#define PAYLOAD

#include "packet_header.hpp"

/* 
 * Payload is currently defined as any application level data, expressed as a 
 * vector of bytes with no semantic structure
*/

class Payload : public PacketHeader
{
    public:
        /* Required Functions */
        void *get_raw();
        void set_raw(void * raw);
        void print_header();
        uint32_t get_header_len();
        void get_bitstring(std::vector<int8_t> &to_fill, int8_t fill_with);
        void get_bitstring_header(std::vector<std::string> &to_fill);

        /* Header Specific Functions */
        void set_info(uint32_t n_bytes, uint32_t max_payload_len);
    private:
        void *raw = NULL;
        uint32_t n_bytes = 0;
        uint32_t max_payload_len = 0;
};

#endif
