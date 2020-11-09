/*
 * Copyright nPrint 2020
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef STATS 
#define STATS 

#include <tuple>
#include <cstdio>
#include <stdint.h>
#include <arpa/inet.h>

class Stats {
    public:
        void print_stats();
        void update(bool parsed, uint8_t network_layer=0, 
                    uint8_t transport_layer=0);
        uint64_t get_packets_processed();
    private:
        uint64_t packets_processed = 0;
        uint64_t packets_parsed = 0;
        uint64_t packets_skipped = 0;
        uint64_t ipv4 = 0;
        uint64_t ipv6 = 0;
        uint64_t tcp = 0;
        uint64_t udp = 0;
        uint64_t icmp = 0;
};

#endif
