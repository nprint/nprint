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
#include "file_writer.hpp"
#include "pcap_parser.hpp"
#include "nprint_parser.hpp"
#include "stringfile_parser.hpp"

const char *argp_program_version = "nprint 1.1.7";
const char *argp_program_bug_address = "https://github.com/nprint/nprint";
static char doc[] =
    "Full information can be found at https://nprint.github.io/nprint/";
static char args_doc[] = "";
static struct argp_option options[] = {
    {"device", 'd', "STRING", 0, "device to capture from if live capture"},
    {"filter", 'f', "STRING", 0, "filter for libpcap"},
    {"count", 'c', "INTEGER", 0, "number of packets to parse (if not all)"},
    {"pcap_file", 'P', "FILE", 0, "pcap infile"},
    {"nPrint_file", 'N', "FILE", 0, "nPrint infile"},
    {"csv_file", 'C', "FILE", 0, "csv (hex packets) infile"},
    {"write_file", 'W', "FILE", 0, "file for output, else stdout"},
    {"nprint_filter", 'x', "STRING", 0, "regex to filter bits out of nPrint. nprint -h for details"},
    {"nprint_filter_help", 'h', 0, 0, "print regex possibilities"},
    {"write_index", 'O', "INTEGER", 0,
     R"""(Output file Index (first column) Options:
                                                  0: source IP (default)
                                                  1: destination IP
                                                  2: source port
                                                  3: destination port
                                                  4: flow (5-tuple)
                                                  5: wlan tx mac)"""},
    {"stats", 'S', 0, 0, "print stats about packets processed when finished"},
    {"fill_int", 'F', "INT8_T", 0, "integer to fill missing bits with"}, 
    {"radiotap", 'r', 0, 0, "include radiotap headers"},
    {"wlan", 'w', 0, 0, "include wlan headers"},
    {"eth", 'e', 0, 0, "include eth headers"},
    {"ipv4", '4', 0, 0, "include ipv4 headers"},
    {"ipv6", '6', 0, 0, "include ipv6 headers"},
    {"tcp", 't', 0, 0, "include tcp headers"},
    {"udp", 'u', 0, 0, "include udp headers"},
    {"icmp", 'i', 0, 0, "include icmp headers"},
    {"payload", 'p', "PAYLOAD_SIZE", 0, "include n bytes of payload"},
    {"absolute_timestamps", 'A', 0, 0, "include absolute timestmap field"},
    {"relative_timestamps", 'R', 0, 0, "include relative timestamp field"},
    {"verbose", 'V', 0, 0, "print human readable packets with nPrints"},
    {0}};
     
const char *filter_help = R"""(
################################################################################
### nPrint Regex Filter Help:
### All field names follow syntax: proto_field_bit
### Each protocol in help follow syntax: proto field numbits

# Ethernet
eth eth_dhost      48
eth eth_shost      48
eth eth_ethertype  16

# IPv4
ipv4 ipv4_ver       4
ipv4 ipv4_hl        4
ipv4 ipv4_tos       8
ipv4 ipv4_tl       16
ipv4 ipv4_id       16
ipv4 ipv4_rbit      1
ipv4 ipv4_dfbit     1
ipv4 ipv4_mfbit     1
ipv4 ipv4_foff     13
ipv4 ipv4_ttl       8
ipv4 ipv4_proto     8
ipv4 ipv4_cksum    16
ipv4 ipv4_src      32
ipv4 ipv4_dst      32
ipv4 ipv4_opt     320

# IPv6
ipv6 ipv6_ver       4
ipv6 ipv6_tc        8
ipv6 ipv6_fl       20
ipv6 ipv6_len      16
ipv6 ipv6_nh        8
ipv6 ipv6_hl        8
ipv6 ipv6_src     128
ipv6 ipv6_dst     128

# TCP 
tcp tcp_sprt       16
tcp tcp_dprt       16
tcp tcp_seq        32
tcp tcp_ackn       32
tcp tcp_doff        4
tcp tcp_res         3
tcp tcp_ns          1
tcp tcp_cwr         1
tcp tcp_ece         1
tcp tcp_urg         1
tcp tcp_ackf        1
tcp tcp_psh         1
tcp tcp_rst         1
tcp tcp_syn         1
tcp tcp_wsize      16
tcp tcp_cksum      16
tcp tcp_urp        16
tcp tcp_opt       320

# UDP
udp udp_sport      16
udp udp_dport      16
udp udp_len        16
udp udp_cksum      16

# ICMP
icmp icmp_type     8
icmp icmp_code     8
icmp icmp_cksum    16
icmp icmp_roh      32

# Payload
payload payload_bit n


### End of nPrint regex filter help, exiting
################################################################################)""";



static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    Config *arguments = (Config *)state->input;
    switch (key) {
    case 'h':
        printf("%s\n", filter_help);
        exit(0);
    case 'A':
        arguments->absolute_timestamps = 1;
        break;
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
    case 'x':
        arguments->regex = arg;
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
    case 'F':
        arguments->fill_with = atoi(arg);
        break;
    case 'S':
        arguments->stats = 1;
        break;
    case 'e':
        arguments->eth = 1;
        break;
    case 'r':
        arguments->radiotap = 1;
        break;
    case 'w':
        arguments->wlan = 1;
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
    case 'O':
        arguments->output_index = atoi(arg);
        if (arguments->output_index > 5 || arguments->output_index < 0) {
            fprintf(stderr, "invald index configuration, exiting\n");
            exit(3);
        }
        break;

    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc};

int main(int argc, char **argv) {
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

    /* No infile means processing live traffic. There is a way to delete this
     * code, but this is verbose */
    if (config.infile == NULL) {
        /* Only time we set this, it's probably better to leave the user to
         * default to live than specify */
        config.live_capture = 1;
        pcap_parser = new PCAPParser();
        pcap_parser->set_filewriter(fw);
        pcap_parser->set_conf(config);
        pcap_parser->process_file();
        if(config.stats == 1) {
            pcap_parser->print_stats();
        }
        delete pcap_parser;
    } else {
        if ((config.pcap + config.csv + config.nprint) > 1) {
            fprintf(stderr, "Only one of {pcap, csv, nprint} input files can "
                            "be selected\n");
            exit(1);
        } else if (config.pcap == 1) {
            pcap_parser = new PCAPParser();
            pcap_parser->set_filewriter(fw);
            pcap_parser->set_conf(config);
            pcap_parser->process_file();
            if(config.stats == 1) {
                pcap_parser->print_stats();
            }
            delete pcap_parser;
        } else if (config.csv == 1) {
            stringfile_parser = new StringfileParser();
            stringfile_parser->set_filewriter(fw);
            stringfile_parser->set_conf(config);
            stringfile_parser->process_file();
            if(config.stats == 1) {
                stringfile_parser->print_stats();
            }
            delete stringfile_parser;
        } else if (config.nprint == 1) {
            /* need an outfile for nprint, can't print pcap to stdout */
            if (config.outfile == NULL) {
                fprintf(stderr, "nprint infile option requires outfile for "
                                "writing reversed pcap\n");
                exit(1);
            } else {
                nprint_parser = new NprintParser();
                nprint_parser->set_conf(config);
                nprint_parser->process_file();
                if(config.stats == 1) {
                    nprint_parser->print_stats();
                }
                delete nprint_parser;
            }
        } else {
            fprintf(stderr, "Unsupported option configuration\n");
            exit(1);
        }
    }
    delete fw;
    return 0;
}


