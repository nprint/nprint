/*
  * Copyright 2020 nPrint
  * Licensed under the Apache License, Version 2.0 (the "License"); you may not
  * use this file except in compliance with the License. You may obtain a copy
  * of the License at https://www.apache.org/licenses/LICENSE-2.0
*/

#include "superpacket.hpp"

void SuperPacket::print_packet()
{
    printf("Superpacket {\n");
    ipv4_header.print_header();
    ipv6_header.print_header();
    tcp_header.print_header();
    udp_header.print_header();
    icmp_header.print_header();
    payload.print_header();
    printf("}\n");
}

SuperPacket::SuperPacket(void *pkt, uint32_t max_payload_len)
{
    struct ip *ipv4h;
    struct ether_header *eth;

    parseable= true;
    this->max_payload_len = max_payload_len;
    eth = (struct ether_header *) pkt;
    /* Check if packet has an ethernet header, skip if so */
    if((ntohs(eth->ether_type) == ETHERTYPE_IP) || ((ntohs(eth->ether_type) == 0x86DD)))
    {
        ipv4h = (struct ip *) &eth[1];
    }
    else
    {
        ipv4h = (struct ip *) pkt;
    }
    
    if(ipv4h->ip_v == 4)
    {
        process_v4((void *) ipv4h);
    }
    else if(ipv4h->ip_v == 6)
    {
        process_v6((void *) ipv4h);
    }
    else
    {
        parseable = false;
    }
}

void SuperPacket::process_v4(void *pkt)
{
    struct ip *ipv4h;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct icmp *icmph;
    void *pload;
    uint32_t pload_len;

    pload = NULL;
    pload_len = 0;

    ipv4h = (struct ip*) pkt;
    ipv4_header.set_raw(ipv4h);
    if(ipv4_header.get_ip_proto() == IPPROTO_TCP)
    {
        tcph = (struct tcphdr *) ((u_char *) ipv4h + ipv4_header.get_header_len());
        tcp_header.set_raw(tcph);
        pload = ((u_char *) tcph + tcp_header.get_header_len());
        pload_len = ipv4_header.get_total_len() - (tcp_header.get_header_len() + ipv4_header.get_header_len());
    }
    else if(ipv4_header.get_ip_proto() == IPPROTO_UDP)
    {
        udph = (struct udphdr *) ((u_char *) ipv4h + ipv4_header.get_header_len());
        udp_header.set_raw(udph);
        pload = ((u_char *) udph + 8);
        pload_len = ipv4_header.get_total_len() - (ipv4_header.get_header_len() + udp_header.get_header_len());
    }
    else if(ipv4_header.get_ip_proto() == IPPROTO_ICMP)
    {
        icmph = (struct icmp *) ((u_char *) ipv4h + ipv4_header.get_header_len());
        icmp_header.set_raw(icmph);
        pload = ((u_char *) icmph + 8);
        pload_len = ipv4_header.get_total_len() - (ipv4_header.get_header_len() + icmp_header.get_header_len());
    }
    payload.set_raw(pload);
    payload.set_info(pload_len, max_payload_len);
}

void SuperPacket::process_v6(void *pkt)
{
    struct ip6_hdr *ipv6h;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct icmp *icmph;
    void *pload;
    uint32_t pload_len;

    pload = NULL;
    pload_len = 0;
    
    ipv6h = (struct ip6_hdr*) pkt;
    ipv6_header.set_raw(ipv6h);

    if(ipv6_header.get_ip_proto() == IPPROTO_TCP)
    {
        tcph = (struct tcphdr *) ((char *) ipv6h + sizeof(struct ip6_hdr));
        tcp_header.set_raw(tcph);
        pload = tcph + tcp_header.get_header_len();
        pload_len = ipv6_header.get_total_len() - (tcp_header.get_header_len() + ipv6_header.get_header_len());
    }
    else if(ipv6_header.get_ip_proto() == IPPROTO_UDP)
    {
        udph = (struct udphdr *) ((char *) ipv6h + sizeof(struct ip6_hdr)); 
        udp_header.set_raw(udph);
        pload = ((u_char *) udph + 8);
        pload_len = ipv6_header.get_total_len() - (udp_header.get_header_len() + ipv6_header.get_header_len());
    }
    else if(ipv6_header.get_ip_proto() == IPPROTO_ICMP)
    {
        icmph = (struct icmp *) ((char *) ipv6h + sizeof(struct ip6_hdr)); 
        icmp_header.set_raw(icmph);
        pload = ((u_char *) icmph + 8);
        pload_len = ipv6_header.get_total_len() - (ipv6_header.get_header_len() + icmp_header.get_header_len());
    }
    payload.set_raw(pload);
    payload.set_info(pload_len, max_payload_len);
}

void SuperPacket::get_bitstring(Config *c, std::vector<int8_t> &to_fill)
{
    if(c->ipv4 == 1) ipv4_header.get_bitstring(to_fill, c->fill_with);
    if(c->ipv6 == 1) ipv6_header.get_bitstring(to_fill, c->fill_with);
    if(c->tcp == 1)  tcp_header.get_bitstring(to_fill,  c->fill_with);
    if(c->udp == 1)  udp_header.get_bitstring(to_fill,  c->fill_with);
    if(c->icmp == 1) icmp_header.get_bitstring(to_fill, c->fill_with);
    if(c->payload != 0) payload.get_bitstring(to_fill,  c->fill_with);
}

std::string SuperPacket::get_ip_address()
{
    if(ipv4_header.get_raw() != NULL)
    {
        return ipv4_header.get_src_ip();
    }
    else if(ipv6_header.get_raw() != NULL)
    {
        return ipv6_header.get_src_ip();
    }
    else
    {
        return "NULL";
    }

}
