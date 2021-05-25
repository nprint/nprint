/*
 * Copyright nPrint 2020
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef FILE_PARSER
#define FILE_PARSER

#include <algorithm>
#include <arpa/inet.h>
#include <map>
#include <string>
#include <vector>
#include <fstream>
#include <csignal>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf.hpp"
#include "file_writer.hpp"
#include "superpacket.hpp"
#include "stats.hpp"

/*
 * File parser abstract class, any input file type that is new must conform to
 * this abstract class definition
 */

class FileParser {
  public:
    virtual ~FileParser(){};
    virtual void process_file() = 0;
    virtual void format_and_write_header() = 0;
    void print_stats();
    void set_conf(Config c);
    void set_filewriter(FileWriter *fw);
    SuperPacket *process_packet(void *pkt);
    void tokenize_line(std::string line, std::vector<std::string> &to_fill,
                       char delimiter = ',');

  protected:
    Stats stat;
    Config config;
    FileWriter *fw;
    uint32_t linktype;
    void write_output(SuperPacket *sp);
    //static void signal_handler(int signum);

    std::vector<std::string> custom_output;
    std::vector<int8_t> bitstring_vec;
    std::vector<std::string> fields_vec;

  private:
    std::string output_type;
};

#endif
