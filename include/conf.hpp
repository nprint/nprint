/*
 * Copyright nPrint 2020
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef CONF
#define CONF

#include <cstddef>
#include <stdint.h>

/* 
 * Config class is a container to hold command line arguments
*/

class Config
{
    public: 
        Config();
        /* Protocol flags */
        uint8_t ipv4;
        uint8_t ipv6;
        uint8_t tcp;
        uint8_t udp;
        uint8_t icmp;
        uint32_t payload;
        uint8_t relative_timestamps;

        /*  Output modification */
        uint8_t csv;
        uint8_t pcap;
        uint8_t nprint;
        int8_t fill_with;
        uint64_t num_packets;
        char *filter;
        char *infile;
        char *outfile;
        char *ip_file;
        char *device;
};

#endif
