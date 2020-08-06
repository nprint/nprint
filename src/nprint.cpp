/*
  * Copyright 2020 nPrint
  * Licensed under the Apache License, Version 2.0 (the "License"); you may not
  * use this file except in compliance with the License. You may obtain a copy
  * of the License at https://www.apache.org/licenses/LICENSE-2.0
*/
#include <argp.h> 
#include <stdio.h>
#include <string.h>

#include <string>

#include "conf.hpp"
#include "pcap_parser.hpp"
#include "file_writer.hpp"
#include "nprint_parser.hpp"
#include "live_parser.hpp"
#include "stringfile_parser.hpp"

const char *argp_program_version = "nprint 1.0.0";
const char *argp_program_bug_address = "https://github.com/nprint/nprint";
static char doc[] = "Full information can be found at https://nprint.github.io/nprint/";
static char args_doc[] = "nprint [OPTIONS]";
static struct argp_option options[] = 
    {
        {"read_file", 'r', "FILE", 0, "file to read from, either PCAP or hex packets"},
        {"write_file", 'w', "FILE", 0, "file for output, else stdout"},
        {"filter", 'f', "STRING", 0, "filter for libpcap"},
        {"count", 'c', "INTEGER", 0, "number of packets to parse (if not all)"},
        {"ip_file", 'q', "FILE", 0, "file of IP addresses to filter with, can be combined with num_packets for num_packets per ip"},
        {"ipv4", '4', 0, 0, "include ipv4 headers"},
        {"ipv6", '6', 0, 0, "include ipv6 headers"},
        {"tcp",  't', 0, 0, "include tcp headers"},
        {"udp",  'u', 0, 0, "include udp headers"},
        {"icmp", 'i', 0, 0, "include icmp headers"},
        {"payload", 'p', "PAYLOAD_SIZE", 0, "include n bytes of payload"},
        {"relative_timestamps", 'r', 0, 0, "include relative timestamp field"},
        {"reverse", 'z', 0, 0, "reverse nPrint to PCAP"},
        { 0 }
    };


static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    Config *arguments = (Config *) state->input;
    switch (key) 
    {
        case 'r':
            arguments->infile = arg;
            break;
        case 'f':
            arguments->filter = arg;
            break;
        case 's':
            arguments->relative_timestamps = 1;
            break;
        case 'w':
            arguments->outfile = arg;
            break;
        case 'c':
            arguments->num_packets = atoi(arg);
            break;
        case '4':
            arguments->ipv4 = 1;
            break;
        case '6':
            arguments->ipv6 = 1;
            break;
        case 'u':
            arguments->udp = 1;
            break;
        case 't':
            arguments->tcp = 1;
            break;
        case 'i':
            arguments->icmp = 1;
            break;
        case 'p':
            arguments->payload = atoi(arg);
            break;
        case 'q':
            arguments->ip_file = arg;
            break;
        case 'z':
            arguments->reverse = 1;
            break;
        default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc};

int main(int argc, char **argv)
{
    FileWriter *fw;
    StringfileParser *stringfile_parser;
    PCAPParser *pcap_parser;
    NprintParser *nprint_parser;
    LiveParser *live_parser;

    Config config;
    
    /* parse args */ 
    argp_parse(&argp, argc, argv, 0, 0, &config);
    
    /* File Writer handles writing nPrints */
    fw = new FileWriter;
    fw->set_conf(config);

    /* No infile means processing live traffic */
    if(config.infile == NULL)
    {
        live_parser = new LiveParser();
        live_parser->set_filewriter(fw);
        live_parser->set_conf(config);
        live_parser->process_file();
    }
    else
    {
        /* PCAP file */
        if(std::string(config.infile).find(".pcap") != std::string::npos)
        {
            pcap_parser = new PCAPParser();
            pcap_parser->set_filewriter(fw);
            pcap_parser->set_conf(config);
            pcap_parser->process_file();
        }
        /* CSV file, either nPrint or hex */
        else if(std::string(config.infile).find(".csv") != std::string::npos)
        {
            if(config.reverse == 1)
            {
                nprint_parser = new NprintParser();
                nprint_parser->set_conf(config);
                nprint_parser->process_file();
            }
            else
            {
                stringfile_parser = new StringfileParser();
                stringfile_parser->set_filewriter(fw);
                stringfile_parser->set_conf(config);
                stringfile_parser->process_file();
            }
        }
        else
        {
            printf("file type unsupported: supported file types: { pcap csv }\n");
            return 1;
       }
    }
    return 0;
}
