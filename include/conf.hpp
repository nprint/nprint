/*
 * Copyright nPrint 2020
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef CONF
#define CONF

#include <map>
#include <string>
#include <cstddef>
#include <stdint.h>

/*
 * Config class is a container to hold command line arguments
 */

class Config {
  public:
    Config();
    /* Protocol flags */
    uint8_t radiotap;
    uint8_t wlan;
    uint8_t eth;
    uint8_t ipv4;
    uint8_t ipv6;
    uint8_t tcp;
    uint8_t udp;
    uint8_t icmp;
    uint32_t payload;

    /* Link-layer types */
    uint8_t wireless;
    uint8_t wired;
    void set_link_layer_type();

    /*  Output modification */
    uint8_t stats;
    uint8_t csv;
    uint8_t pcap;
    uint8_t nprint;
    uint8_t verbose;
    uint8_t live_capture;
    uint8_t output_index;
    uint8_t absolute_timestamps;
    uint8_t relative_timestamps;
    int8_t fill_with;
    uint64_t num_packets;
    char *device;
    char *filter;
    char *regex;
    char *infile;
    char *ip_file;
    char *outfile;
    std::map<int8_t, std::string> index_map = {{0, "src_ip"},
                                                {1, "dst_ip"},
                                                {2, "src_prt"},
                                                {3, "dst_prt"},
                                                {4, "flow"},
                                                {5, "tx_mac"}};
};

#endif
