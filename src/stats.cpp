#include "stats.hpp"

void Stats::print_stats() {
    fprintf(stderr, "General Statistics\n");
    fprintf(stderr, "  Packets processed: %10llu\n", (unsigned long long) packets_processed);
    fprintf(stderr, "  Packets skipped:   %10llu (%.2f%%)\n", (unsigned long long) packets_skipped, 100.0 * (double(packets_skipped) / packets_processed));
    fprintf(stderr, "  Packets parsed:    %10llu (%.2f%%)\n", (unsigned long long) packets_parsed, 100.0 * (double(packets_parsed) / packets_processed));
    fprintf(stderr, "Network Layer Statistics (of packets parsed)\n");
    fprintf(stderr, "  IPv4:              %10llu (%.2f%%)\n", (unsigned long long) ipv4, 100.0 * (double(ipv4) / packets_parsed));
    fprintf(stderr, "  IPv6:              %10llu (%.2f%%)\n", (unsigned long long) ipv6, 100.0 * (double(ipv6) / packets_parsed));
    fprintf(stderr, "Transport Layer Statistics (of packets parsed)\n");
    fprintf(stderr, "  TCP:               %10llu (%.2f%%)\n", (unsigned long long) tcp, 100.0 * (double(tcp) / packets_parsed));
    fprintf(stderr, "  UDP:               %10llu (%.2f%%)\n", (unsigned long long) udp, 100.0 * (double(udp) / packets_parsed));
    fprintf(stderr, "  ICMP:              %10llu (%.2f%%)\n", (unsigned long long) icmp, 100.0 * (double(icmp) / packets_parsed));
    fprintf(stderr, "Application Layer Statistics (of packets parsed)\n");
    fprintf(stderr, "  DNS:               %10llu (%.2f%%)\n", (unsigned long long) dns, 100.0 * (double(dns) / packets_parsed));
    fprintf(stderr, "  DHCP:               %10llu (%.2f%%)\n", (unsigned long long) dhcp, 100.0 * (double(dns) / packets_parsed));
}

void Stats::update(bool parsed, uint8_t network_layer, uint8_t transport_layer, uint16_t sport, uint16_t dport) {
    packets_processed++;
    if (!parsed) {
        packets_skipped++;
    } else {
        packets_parsed++;
        if (network_layer == 4) ipv4++;
        if (network_layer == 6) ipv6++;
        if (transport_layer == IPPROTO_TCP) tcp++;
        if (transport_layer == IPPROTO_UDP) udp++;
        if (transport_layer == IPPROTO_ICMP) icmp++;
        if (transport_layer == IPPROTO_UDP && (sport == 53 || dport == 53)) dns++;
        if (transport_layer == IPPROTO_UDP && (sport == 67 || sport == 68 || dport == 67 || dport == 68)) dhcp++;

}
}

uint64_t Stats::get_packets_processed() {
    return packets_processed;
}

