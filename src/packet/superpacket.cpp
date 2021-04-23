/*
 * Copyright 2020 nPrint
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at https://www.apache.org/licenses/LICENSE-2.0
 */

#include "superpacket.hpp"

void SuperPacket::print_packet(FILE *out) {
    fprintf(out, "Superpacket {\n");
    radiotap_header.print_header(out);
    wlan_header.print_header(out);
    ethernet_header.print_header(out);
    ipv4_header.print_header(out);
    ipv6_header.print_header(out);
    tcp_header.print_header(out);
    udp_header.print_header(out);
    icmp_header.print_header(out);
    payload.print_header(out);
    fprintf(out, "}\n");
}

SuperPacket::SuperPacket(void *pkt, uint32_t max_payload_len, Config *c) {
    struct radiotap_header *radiotaph;
    struct wlan_header * wlanh;

    struct ip *ipv4h;
    struct ether_header *eth;

    this->config = c;

    parseable = true;

    if (c->wireless == 1) {
        radiotaph = (struct radiotap_header *) pkt;
        radiotap_header.set_raw(radiotaph);

        wlanh = (struct wlan_header *) &radiotaph[1]; 
        wlan_header.set_raw(wlanh);        
    } else if (c->wired == 1) {
        this->max_payload_len = max_payload_len;
        eth = (struct ether_header *)pkt;

        /* Check if packet has an ethernet header */
        if ((ntohs(eth->ether_type) == ETHERTYPE_IP) ||
            ((ntohs(eth->ether_type) == 0x86DD))) {
            ethernet_header.set_raw(eth);
            ipv4h = (struct ip *)&eth[1];
        } else {
            ipv4h = (struct ip *)pkt;
        }

        if (ipv4h->ip_v == 4) {
            parseable = process_v4((void *)ipv4h);
        } else if (ipv4h->ip_v == 6) {
            parseable = process_v6((void *)ipv4h);
        } else {
            parseable = false;
        }
    }
}

bool SuperPacket::process_v4(void *pkt) {
    struct ip *ipv4h;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct icmp *icmph;
    void *pload;
    uint32_t pload_len;

    pload = NULL;
    pload_len = 0;

    ipv4h = (struct ip *)pkt;
    ipv4_header.set_raw(ipv4h);
    if (ipv4_header.get_ip_proto() == IPPROTO_TCP) {
        tcph =
            (struct tcphdr *)((u_char *)ipv4h + ipv4_header.get_header_len());
        tcp_header.set_raw(tcph);
        pload = ((u_char *)tcph + tcp_header.get_header_len());
        pload_len =
            ipv4_header.get_total_len() -
            (tcp_header.get_header_len() + ipv4_header.get_header_len());
    } else if (ipv4_header.get_ip_proto() == IPPROTO_UDP) {
        udph =
            (struct udphdr *)((u_char *)ipv4h + ipv4_header.get_header_len());
        udp_header.set_raw(udph);
        pload = ((u_char *)udph + udp_header.get_header_len());
        pload_len =
            ipv4_header.get_total_len() -
            (ipv4_header.get_header_len() + udp_header.get_header_len());
    } else if (ipv4_header.get_ip_proto() == IPPROTO_ICMP) {
        icmph = (struct icmp *)((u_char *)ipv4h + ipv4_header.get_header_len());
        icmp_header.set_raw(icmph);
        pload = ((u_char *)icmph + icmp_header.get_header_len());
        pload_len =
            ipv4_header.get_total_len() -
            (ipv4_header.get_header_len() + icmp_header.get_header_len());
    } else {
        return false;
    }
    payload.set_raw(pload);
    payload.set_info(pload_len, max_payload_len);

    return true;
}

bool SuperPacket::process_v6(void *pkt) {
    struct ip6_hdr *ipv6h;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct icmp *icmph;
    void *pload;
    uint32_t pload_len;

    pload = NULL;
    pload_len = 0;

    ipv6h = (struct ip6_hdr *)pkt;
    ipv6_header.set_raw(pkt);

    if (ipv6_header.get_ip_proto() == IPPROTO_TCP) {
        tcph =
            (struct tcphdr *)((u_char *)ipv6h + ipv6_header.get_header_len());
        tcp_header.set_raw(tcph);
        pload = tcph + tcp_header.get_header_len();
        pload_len =
            ipv6_header.get_total_len() -
            (tcp_header.get_header_len() + ipv6_header.get_header_len());
    } else if (ipv6_header.get_ip_proto() == IPPROTO_UDP) {
        udph =
            (struct udphdr *)((u_char *)ipv6h + ipv6_header.get_header_len());
        udp_header.set_raw(udph);
        pload = ((u_char *)udph + 8);
        pload_len =
            ipv6_header.get_total_len() -
            (udp_header.get_header_len() + ipv6_header.get_header_len());
    } else if (ipv6_header.get_ip_proto() == IPPROTO_ICMP) {
        icmph = (struct icmp *)((u_char *)ipv6h + ipv6_header.get_header_len());
        icmp_header.set_raw(icmph);
        pload = ((u_char *)icmph + 8);
        pload_len =
            ipv6_header.get_total_len() -
            (ipv6_header.get_header_len() + icmp_header.get_header_len());
    } else {
        return false;
    }
    payload.set_raw(pload);
    payload.set_info(pload_len, max_payload_len);

    return true;
}

void SuperPacket::get_bitstring(Config *c, std::vector<int8_t> &to_fill) {
    if (c->radiotap == 1)
        radiotap_header.get_bitstring(to_fill, c->fill_with);
    if (c->wlan == 1)
        radiotap_header.get_bitstring(to_fill, c->fill_with);
    if (c->eth == 1)
        ethernet_header.get_bitstring(to_fill, c->fill_with);
    if (c->ipv4 == 1)
        ipv4_header.get_bitstring(to_fill, c->fill_with);
    if (c->ipv6 == 1)
        ipv6_header.get_bitstring(to_fill, c->fill_with);
    if (c->tcp == 1)
        tcp_header.get_bitstring(to_fill, c->fill_with);
    if (c->udp == 1)
        udp_header.get_bitstring(to_fill, c->fill_with);
    if (c->icmp == 1)
        icmp_header.get_bitstring(to_fill, c->fill_with);
    if (c->payload != 0)
        payload.get_bitstring(to_fill, c->fill_with);
}

std::string SuperPacket::get_index(Config *c) {
    std::string rv;
    /* Source IP */
    /* Could switch here... */
    if (c->output_index == 0) {
        rv = get_ip_address(true);
    }
    /* DST IP */
    else if (c->output_index == 1) {
        rv = get_ip_address(false);
    }
    /* Source Port */
    else if (c->output_index == 2) {
        rv = get_port(true);
    }
    /* Dest Port */
    else if (c->output_index == 3) {
        rv = get_port(false);
    }
    /* Flow */
    else if (c->output_index == 4) {
        /* There is 99% probability a better way to do this. */
        rv = get_ip_address(true);
        rv += std::string("_") + get_ip_address(false);
        rv += std::string("_") + get_port(true);
        rv += std::string("_") + get_port(false);
        if (tcp_header.get_raw() != NULL) {
            rv += std::string("_") + "TCP";
        } else if (udp_header.get_raw() != NULL) {
            rv += std::string("_") + "UDP";
        } else {
            rv += std::string("_") + "NULL";
        }
    }
    /* Wlan TX Mac Address */
    else if (c->index == 5) {
        rv = get_tx_mac_address();
    }

    return rv;
}

std::string SuperPacket::get_ip_address(bool src) {
    if (ipv4_header.get_raw() != NULL) {
        if (src) {
            return ipv4_header.get_src_ip();
        } else {
            return ipv4_header.get_dst_ip();
        }
    } else if (ipv6_header.get_raw() != NULL) {
        if (src) {
            return ipv6_header.get_src_ip();
        } else {
            return ipv6_header.get_dst_ip();
        }
    } else {
        return "NULL";
    }
}

std::string SuperPacket::get_port(bool src) {
    if (tcp_header.get_raw() != NULL) {
        return tcp_header.get_port(src);
    } else if (udp_header.get_raw() != NULL) {
        return udp_header.get_port(src);
    } else {
        return "NULL";
    }
}

std::string SuperPacket::get_tx_mac_address() {
    if(wlan_header.get_raw() != NULL) {
        return wlan_header.get_tx_mac();
    } else {
        return "NULL";
    }
}

std::tuple<uint8_t, uint8_t> SuperPacket::get_packet_type() {
    uint8_t network_layer, transport_layer;

    if (ipv4_header.get_raw() != NULL) {
        network_layer = 4;
        transport_layer = ipv4_header.get_ip_proto();
    }
    else if(ipv6_header.get_raw() != NULL) {
        network_layer = 6;
        transport_layer = ipv6_header.get_ip_proto();
    }
    else {
        network_layer = 0;
        transport_layer = 0;
    }

    return std::tuple<uint8_t, uint8_t>(network_layer, transport_layer);
}
