/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "pcap_parser.hpp"

PCAPParser::PCAPParser() {
    mrt.tv_sec = 0;
    mrt.tv_usec = 0;
    to_fill.reserve(((SIZE_IPV4_HEADER_BITSTRING + SIZE_TCP_HEADER_BITSTRING +
                      SIZE_UDP_HEADER_BITSTRING + SIZE_ICMP_HEADER_BITSTRING) *
                     8) *
                    4);
}

void PCAPParser::process_file() {
    pcap_t *f;

    f = get_pcap_handle();
    pcap_loop(f, 0, packet_handler, (u_char *)this);
    pcap_close(f);
}

void PCAPParser::packet_handler(u_char *user_data,
                                const struct pcap_pkthdr *pkthdr,
                                const u_char *packet) {
    PCAPParser *pcp;
    SuperPacket *sp;
    int64_t rts;

    pcp = (PCAPParser *)user_data;

    sp = pcp->process_packet((void *)packet);
    if (sp == NULL)
        return;
    rts = pcp->process_timestamp(pkthdr->ts);

    pcp->custom_output.push_back(sp->get_index(&(pcp->config)));
    if (rts != -1)
        pcp->custom_output.push_back(std::to_string(rts));
    if (pcp->config.absolute_timestamps) {
        pcp->custom_output.push_back(std::to_string(pkthdr->ts.tv_sec));
        pcp->custom_output.push_back(std::to_string(pkthdr->ts.tv_usec));
    }
    pcp->write_output(sp);
}

void PCAPParser::format_and_write_header() {
    std::vector<std::string> header;
    header.push_back(config.index_map.find(config.index)->second);
    if (config.relative_timestamps == 1)
        header.push_back("rts");
    if (config.absolute_timestamps == 1) {
        header.push_back("tv_sec");
        header.push_back("tv_usec");
    }

    fw->write_header(header);
}

int64_t PCAPParser::process_timestamp(struct timeval ts) {
    int64_t rts;

    if (config.relative_timestamps == 0)
        return -1;

    if (mrt.tv_sec == 0) {
        rts = 0;
    } else {
        rts = (1000000 * (ts.tv_sec - mrt.tv_sec)) + ts.tv_usec - mrt.tv_usec;
    }

    mrt = ts;
    return rts;
}

pcap_t *PCAPParser::get_pcap_handle() {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *f;

    if (config.live_capture == 0) {
        f = pcap_open_offline_with_tstamp_precision(
            config.infile, PCAP_TSTAMP_PRECISION_MICRO, errbuf);
    } else {
        f = open_live_handle();
    }

    return f;
}

pcap_t *PCAPParser::open_live_handle() {
    int32_t rv;
    pcap_t *handle;
    pcap_if_t *l;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    /* get device */
    if (config.device == NULL) {
        rv = pcap_findalldevs(&l, errbuf);
        if (rv == -1) {
            fprintf(stderr, "Failure looking up default device: %s\n", errbuf);
            exit(2);
        }
        config.device = l->name;
    }
    if (config.filter != NULL) {
        /* get mask*/
        if (pcap_lookupnet(config.device, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Can't get netmask for device %s\n", config.device);
            net = 0;
            mask = 0;
        }
    }
    /* open device */
    handle = pcap_open_live(config.device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        exit(2);
    }
    if (config.filter != NULL) {
        if (pcap_compile(handle, &fp, config.filter, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", config.filter,
                    pcap_geterr(handle));
            exit(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", config.filter,
                    pcap_geterr(handle));
            exit(2);
        }
    }

    return handle;
}
