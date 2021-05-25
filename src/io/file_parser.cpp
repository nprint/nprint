/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "file_parser.hpp"

#define CUSTOM_OUTPUT_RESERVE_SIZE 50
#define BITSTRING_RESERVE_SIZE 10000

void FileParser::set_conf(Config c) {
    this->config = c;

    /* Write header when we set the config */
    format_and_write_header();

    /* Reserve vectors and use them the entire time */
    custom_output.reserve(CUSTOM_OUTPUT_RESERVE_SIZE);
    bitstring_vec.reserve(BITSTRING_RESERVE_SIZE);
}

void FileParser::set_filewriter(FileWriter *fw) {
    this->fw = fw;
}

void FileParser::tokenize_line(std::string line,
                               std::vector<std::string> &to_fill,
                               char delimiter) {
    std::string token;
    std::stringstream ss;

    to_fill.clear();
    ss.str(line);
    while (getline(ss, token, delimiter))
        to_fill.push_back(token);
}

SuperPacket *FileParser::process_packet(void *pkt) {
    bool parseable;
    SuperPacket *sp;
    std::string src_ip;
    std::vector<std::string> to_fill;
    std::map<std::string, std::uint32_t>::iterator mit;
    uint8_t network_layer, transport_layer;

    to_fill.clear();
    sp = new SuperPacket(pkt, config.payload, linktype);
    parseable = sp->check_parseable();
    if (!parseable) {
        delete sp;
        sp = NULL;
        network_layer = 0;
        transport_layer = 0;
    }
    else {
        if (config.verbose)
            sp->print_packet(stderr);
        /* Exit when done */
        if (config.num_packets != 0 && stat.get_packets_processed() >= config.num_packets)
            exit(0);
        std::tie(network_layer, transport_layer) = sp->get_packet_type();
    }
    
    stat.update(parseable, network_layer, transport_layer);
    
    return sp;
}

void FileParser::write_output(SuperPacket *sp) {
    sp->get_bitstring(&config, bitstring_vec);
    fw->write_bitstring_line(custom_output, bitstring_vec);
    bitstring_vec.clear();
    custom_output.clear();
    
    delete sp;
}

void FileParser::print_stats() {
    stat.print_stats();
}
