/*
 * Copyright nPrint 2020
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef STRINGFILE_PARSER
#define STRINGFILE_PARSER

#include "file_parser.hpp"

/*
 * StringfileParser parses hex encoded packets in a CSV.For example, the
 * output of a zmap scan
 */

class StringfileParser : public FileParser {
  public:
    void process_file();
    void format_and_write_header();

  private:
    uint32_t num_cols;
    int hex_value(char hex_digit);
    void format_custom_output(std::vector<std::string> &tokens);
    std::string hex_to_string(std::string input);
};

#endif
