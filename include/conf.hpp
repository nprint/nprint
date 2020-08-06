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
        uint8_t ipv4;
        uint8_t ipv6;
        uint8_t tcp;
        uint8_t udp;
        uint8_t icmp;
        uint8_t reverse;
        uint32_t payload;
        int8_t fill_with;
        uint64_t num_packets;
        uint8_t relative_timestamps;
        char *filter;
        char *infile;
        char *outfile;
        char *ip_file;
        char *device;
};

#endif
