/*
  * Copyright 2020 nPrint
  * Licensed under the Apache License, Version 2.0 (the "License"); you may not
  * use this file except in compliance with the License. You may obtain a copy
  * of the License at https://www.apache.org/licenses/LICENSE-2.0
*/

#include "live_parser.hpp"

LiveParser::LiveParser()
{
    mrt = 0;
    to_fill.reserve(((SIZE_IPV4_HEADER_BITSTRING + SIZE_TCP_HEADER_BITSTRING + SIZE_UDP_HEADER_BITSTRING + SIZE_ICMP_HEADER_BITSTRING) * 8) * 4);
}

void LiveParser::process_file()
{
    uint32_t rv;
    pcap_t *handle;
    pcap_if_t *l;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    
    /* get device */
    if(config.device == NULL)
    {
        rv = pcap_findalldevs(&l, errbuf);
        if(rv == -1)
        {
            fprintf(stderr, "Failure looking up default device: %s\n", errbuf);
            exit(2);
        }
        config.device = l->name;
    }
    if(config.filter != NULL)
    {
        /* get mask*/
        if (pcap_lookupnet(config.device, &net, &mask, errbuf) == -1) 
        {
            fprintf(stderr, "Can't get netmask for device %s\n", config.device);
            net = 0;
            mask = 0;
        }
    }
    /* open device */
    handle = pcap_open_live(config.device, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL)
    {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        exit(2);
    }
    if(config.filter != NULL)
    {
        if (pcap_compile(handle, &fp, config.filter, 0, net) == -1) 
        {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", config.filter, pcap_geterr(handle));
            exit(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) 
        {
             fprintf(stderr, "Couldn't install filter %s: %s\n", config.filter, pcap_geterr(handle));
             exit(2);
        }
    }

    if(pcap_loop(handle, 0, packet_handler, (u_char *) this) < 0) return;
}

void LiveParser::packet_handler(u_char *user_data, const struct pcap_pkthdr* pkthdr,
                                const u_char *packet)
{
    LiveParser *pcp;
    SuperPacket *sp;
    int64_t rts;

    pcp = (LiveParser *) user_data;
    
    sp = pcp->process_packet((void *) packet);
    if(sp == NULL) return;
    rts = pcp->process_timestamp(pkthdr->ts.tv_sec);

    pcp->custom_output.push_back(sp->get_ip_address());
    if(rts != -1) pcp->custom_output.push_back(std::to_string(rts));
    pcp->write_output(sp);
}

void LiveParser::format_and_write_header()
{
    std::vector<std::string> header;
    header.push_back("ip");
    if(config.relative_timestamps == 1) header.push_back("rts");

    fw->write_header(header);
}

int64_t LiveParser::process_timestamp(uint32_t ts)
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
