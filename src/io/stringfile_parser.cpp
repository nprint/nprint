/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "stringfile_parser.hpp"

#define SFILE_IP_LOC 0
#define SFILE_HXP_LOC 2

void StringfileParser::process_file() {
    std::string line, pkt;
    std::vector<std::string> tokens;
    SuperPacket *sp;

    std::ifstream instream(config.infile);
    /* skip header */
    getline(instream, line);
    while (getline(instream, line)) {
        tokenize_line(line, tokens, ',');
        try {
            pkt = hex_to_string(tokens[SFILE_HXP_LOC]);
        } catch (const std::invalid_argument &ia) {
            printf("Error parsing line: %s, skipping\n", line.c_str());
            continue;
        }
        sp = process_packet((void *)pkt.c_str());
        if (sp == NULL)
            return;
        format_custom_output(tokens);
        write_output(sp);
    }
}

std::string StringfileParser::hex_to_string(std::string input) {
    size_t len = input.length();
    if (len & 1)
        throw std::invalid_argument("odd length");

    std::string out;
    out.reserve(len / 2);
    for (auto it = input.begin(); it != input.end();) {
        int hi = hex_value(*it++);
        int lo = hex_value(*it++);
        out.push_back(hi << 4 | lo);
    }

    return out;
}

void StringfileParser::format_custom_output(std::vector<std::string> &tokens) {
    uint32_t i;

    /* line prefix */
    for (i = 0; i < num_cols; i++)
        custom_output.push_back(tokens[i]);
}

int StringfileParser::hex_value(char hex_digit) {
    switch (hex_digit) {
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
        return hex_digit - '0';

    case 'A':
    case 'B':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
        return hex_digit - 'A' + 10;

    case 'a':
    case 'b':
    case 'c':
    case 'd':
    case 'e':
    case 'f':
        return hex_digit - 'a' + 10;
    }
    throw std::invalid_argument("invalid hex digit");
}

void StringfileParser::format_and_write_header() {
    std::string line, pkt;
    std::vector<std::string> tokens, header;
    uint32_t i;

    std::ifstream instream(config.infile);
    getline(instream, line);
    tokenize_line(line, tokens, ',');
    for (i = 0; i < tokens.size(); i++)
        header.push_back(tokens[i]);

    num_cols = i;

    instream.close();
    fw->write_header(header);
}
