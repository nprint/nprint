/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */
#include "conf.hpp"

Config::Config() {
    this->radiotap = 0;
    this->wlan = 0;
    this->eth = 0;
    this->ipv4 = 0;
    this->ipv6 = 0;
    this->tcp = 0;
    this->udp = 0;
    this->icmp = 0;
    this->payload = 0;
    this->fill_with = -1;
    this->num_packets = 0;
    this->absolute_timestamps = 0;
    this->relative_timestamps = 0;
    this->pcap = 0;
    this->csv = 0;
    this->wireless = 0;
    this->wired = 0;
    this->stats = 0;
    this->nprint = 0;
    this->verbose = 0;
    this->live_capture = 0;
    this->output_index = 0;
    this->regex = NULL;
    this->infile = NULL;
    this->filter = NULL;
    this->ip_file = NULL;
    this->outfile = NULL;
    this->device = NULL;
}

void Config::set_link_layer_type() {
    if ((this->radiotap + this->wlan) > 0) {
        this->wireless = 1;
    }
    if ((this->eth + this->ipv4 + this->ipv6 + this->tcp + this->udp + this->icmp) > 0) {
        this->wired = 1;
    }
}
