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
#include "stringfile_parser.hpp"

const char *argp_program_version = "nprint 1.0.4";
const char *argp_program_bug_address = "https://github.com/nprint/nprint";
static char doc[] = "Full information can be found at https://nprint.github.io/nprint/";
static char args_doc[] = "";
static struct argp_option options[] = 
    {
        {"device", 'd', "STRING", 0, "device to capture from if live capture"},
        {"filter", 'f', "STRING", 0, "filter for libpcap"},
        {"count", 'c', "INTEGER", 0, "number of packets to parse (if not all)"},
        {"pcap_file", 'P', "FILE", 0, "pcap infile"},
        {"nPrint_file", 'N', "FILE", 0, "nPrint infile"},
        {"csv_file", 'C', "FILE", 0, "csv (hex packets) infile"},
        {"write_file", 'W', "FILE", 0, "file for output, else stdout"},
        {"ip_file", 'I', "FILE", 0, "file of IP addresses to filter with (1 per line), can be combined with num_packets for num_packets per ip"},
        {"eth",  'e', 0, 0, "include eth headers"},
        {"ipv4", '4', 0, 0, "include ipv4 headers"},
        {"ipv6", '6', 0, 0, "include ipv6 headers"},
        {"tcp",  't', 0, 0, "include tcp headers"},
        {"udp",  'u', 0, 0, "include udp headers"},
        {"icmp", 'i', 0, 0, "include icmp headers"},
        {"payload", 'p', "PAYLOAD_SIZE", 0, "include n bytes of payload"},
        {"relative_timestamps", 'R', 0, 0, "include relative timestamp field"},
        {"verbose", 'V', 0, 0, "print human readable packets with nPrints"},
        { 0 }
    };

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    Config *arguments = (Config *) state->input;
    switch (key) 
    {
        case 'V':
            arguments->verbose = 1;
            break;
        case 'd':
            arguments->device = arg;
            break;
        case 'f':
            arguments->filter = arg;
            break;
        case 'c':
            arguments->num_packets = atoi(arg);
            break;
        case 'P':
            arguments->infile = arg;
            arguments->pcap = 1;
            break;
        case 'N':
            arguments->infile = arg;
            arguments->nprint = 1;
            break;
        case 'C':
            arguments->infile = arg;
            arguments->csv = 1;
            break;
        case 'W':
            arguments->outfile = arg;
            break;
        case 'I':
            arguments->ip_file = arg;
            break;
        case 'e':
            arguments->eth = 1;
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
        case 'R':
            arguments->relative_timestamps = 1;
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

    Config config;
    
    /* parse args */ 
    argp_parse(&argp, argc, argv, 0, 0, &config);
    
    /* File Writer handles writing nPrints */
    fw = new FileWriter;
    fw->set_conf(config);
    
    /* No infile means processing live traffic. There is a way to delete this code, but this is verbose */
    if(config.infile == NULL)
    {
        /* Only time we set this, it's probably better to leave the user to default to live than specify */
        config.live_capture = 1;
        pcap_parser = new PCAPParser();
        pcap_parser->set_filewriter(fw);
        pcap_parser->set_conf(config);
        pcap_parser->process_file();
        delete pcap_parser;
    }
    else
    {
        if((config.pcap + config.csv + config.nprint) > 1)
        {
            fprintf(stderr, "Only one of {pcap, csv, nprint} input files can be selected\n");
            exit(1);
        }
        else if(config.pcap == 1)
        {
            pcap_parser = new PCAPParser();
            pcap_parser->set_filewriter(fw);
            pcap_parser->set_conf(config);
            pcap_parser->process_file();
            delete pcap_parser;
        }
        else if(config.csv == 1)
        {
            stringfile_parser = new StringfileParser();
            stringfile_parser->set_filewriter(fw);
            stringfile_parser->set_conf(config);
            stringfile_parser->process_file();
            delete stringfile_parser;
        }
        else if(config.nprint == 1)
        {
            /* need an outfile for nprint, can't print pcap to stdout */
            if(config.outfile == NULL)
            {
                fprintf(stderr, "nprint infile option requires outfile for writing reversed pcap\n");
                exit(1);
            }
            else
            {
                nprint_parser = new NprintParser();
                nprint_parser->set_conf(config);
                nprint_parser->process_file();
                delete nprint_parser;
            }
        }
        else
        {
            fprintf(stderr, "Unsupported option configuration\n");
            exit(1);
        }
    }
    delete fw;
    return 0;
}
