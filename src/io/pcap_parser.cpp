/*
  * Copyright 2020 nPrint
  * Licensed under the Apache License, Version 2.0 (the "License"); you may not
  * use this file except in compliance with the License. You may obtain a copy
  * of the License at https://www.apache.org/licenses/LICENSE-2.0
*/

#include "pcap_parser.hpp"

PCAPParser::PCAPParser()
{
    mrt = 0;
    to_fill.reserve(((SIZE_IPV4_HEADER_BITSTRING + SIZE_TCP_HEADER_BITSTRING + SIZE_UDP_HEADER_BITSTRING + SIZE_ICMP_HEADER_BITSTRING) * 8) * 4);
}

void PCAPParser::process_file()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *f = pcap_open_offline_with_tstamp_precision(config.infile, 
                                                        PCAP_TSTAMP_PRECISION_MICRO,
                                                        errbuf);

    if(pcap_loop(f, 0, packet_handler, (u_char *) this) < 0) return;
}

void PCAPParser::packet_handler(u_char *user_data, const struct pcap_pkthdr* pkthdr,
                                const u_char *packet)
{
    PCAPParser *pcp;
    SuperPacket *sp;
    int64_t rts;

    pcp = (PCAPParser *) user_data;
    
    sp = pcp->process_packet((void *) packet);
    if(sp == NULL) return;
    rts = pcp->process_timestamp(pkthdr->ts.tv_sec);

    pcp->custom_output.push_back(sp->get_ip_address());
    if(rts != -1) pcp->custom_output.push_back(std::to_string(rts));
    pcp->write_output(sp);
}

void PCAPParser::format_and_write_header()
{
    std::vector<std::string> header;
    header.push_back("ip");
    if(config.relative_timestamps == 1) header.push_back("rts");

    fw->write_header(header);
}

int64_t PCAPParser::process_timestamp(uint32_t ts)
{
    int64_t rts;
    
    if(config.relative_timestamps == 0) return -1;

    if(mrt == 0)
    {
        mrt = ts;
        rts = 0;
    }
    else
    {
        rts = ts - mrt;
        mrt = ts;
    }

    return rts;
}
