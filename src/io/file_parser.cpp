/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "file_parser.hpp"

#define CUSTOM_OUTPUT_RESERVE_SIZE 50
#define BITSTRING_RESERVE_SIZE 10000
#define FIELDS_RESERVE_SIZE 300

void FileParser::set_conf(Config c) {
    packets_processed = 0;
    this->config = c;

    /* Write header when we set the config */
    format_and_write_header();

    /* Reserve vectors and use them the entire time */
    custom_output.reserve(CUSTOM_OUTPUT_RESERVE_SIZE);
    bitstring_vec.reserve(BITSTRING_RESERVE_SIZE);
    fields_vec.reserve(FIELDS_RESERVE_SIZE);
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
    SuperPacket *sp;
    std::string src_ip;
    std::vector<std::string> to_fill;
    std::map<std::string, std::uint32_t>::iterator mit;

    to_fill.clear();
    sp = new SuperPacket(pkt, config.payload);
    if (!sp->check_parseable()) {
        delete sp;
        return NULL;
    }

    if (config.verbose)
        sp->print_packet();
    /* Exit when done */
    if (config.num_packets != 0 && packets_processed >= config.num_packets)
        exit(0);
    packets_processed++;

    return sp;
}

void FileParser::write_output(SuperPacket *sp) {
    sp->get_bitstring(&config, bitstring_vec);
    fw->write_bitstring_line(custom_output, bitstring_vec);
    bitstring_vec.clear();
    custom_output.clear();
    delete sp;
}
