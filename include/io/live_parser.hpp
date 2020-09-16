/*
 * Copyright nPrint 2020
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef LIVE_PARSER 
#define LIVE_PARSER


#if defined(__NetBSD__)
#include <net/if_ether.h>
#else
#include <net/ethernet.h>
#endif

#include <pcap.h>

#include "file_parser.hpp"

/*
 * LiveParser hooks to an interface and creates nPrints in real time
*/

class LiveParser : public FileParser
{
    public: 
        LiveParser();
        void process_file();
        void format_and_write_header();
        static void packet_handler(u_char *user_data, const struct pcap_pkthdr* pkthdr,
                                   const u_char* packet);
        int64_t process_timestamp(struct timeval ts);
    private:
        std::vector<std::string> to_fill;
        struct timeval mrt;
};

#endif
