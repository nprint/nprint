#include "stats.hpp"

void Stats::print_stats() {
    fprintf(stderr, "General Statistics\n");
    fprintf(stderr, "  Packets processed: %10lu\n", packets_processed);
    fprintf(stderr, "  Packets skipped:   %10lu (%.2f%%)\n", packets_skipped, 100.0 * (double(packets_skipped) / packets_processed));
    fprintf(stderr, "  Packets parsed:    %10lu (%.2f%%)\n", packets_parsed, 100.0 * (double(packets_parsed) / packets_processed));
    fprintf(stderr, "Network Layer Statistics (of packets parsed)\n");
    fprintf(stderr, "  IPv4:              %10lu (%.2f%%)\n", ipv4, 100.0 * (double(ipv4) / packets_parsed));
    fprintf(stderr, "  IPv6:              %10lu (%.2f%%)\n", ipv6, 100.0 * (double(ipv6) / packets_parsed));
    fprintf(stderr, "Transport Layer Statistics (of packets parsed)\n");
    fprintf(stderr, "  TCP:               %10lu (%.2f%%)\n", tcp, 100.0 * (double(tcp) / packets_parsed));
    fprintf(stderr, "  UDP:               %10lu (%.2f%%)\n", udp, 100.0 * (double(udp) / packets_parsed));
    fprintf(stderr, "  ICMP:              %10lu (%.2f%%)\n", icmp, 100.0 * (double(icmp) / packets_parsed));
}

void Stats::update(bool parsed, uint8_t network_layer, uint8_t transport_layer) {
    packets_processed++;
    if(!parsed) {
        packets_skipped++; 
    } else {
        packets_parsed++;
        if(network_layer == 4) ipv4++;
        if(network_layer == 6) ipv6++;
        if(transport_layer == IPPROTO_TCP) tcp++;
        if(transport_layer == IPPROTO_UDP) udp++;
        if(transport_layer == IPPROTO_ICMP) icmp++;
    }
}

uint64_t Stats::get_packets_processed() {
    return packets_processed;
}
