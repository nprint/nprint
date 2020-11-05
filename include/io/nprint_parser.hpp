/*
 * Copyright nPrint 2020
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef NPRINT_PARSER
#define NPRINT_PARSER

#include <tuple>

#include <netinet/ip.h>
#include <pcap.h>

#include "file_parser.hpp"
#include "superpacket.hpp"

/*
 * NprintParser is used to transform any nPrint back to a PCAP
 */

class NprintParser : public FileParser {
  public:
    void process_file();
    void format_and_write_header();

  private:
    std::string clean_line(std::string &line);
    uint8_t *transform_bitstring(std::string &bits);
    std::tuple<void *, uint64_t> parse_packet(std::string &bits);
};

#endif
