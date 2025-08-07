AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = nprint

nprint_SOURCES = src/conf.cpp src/nprint.cpp src/io/file_parser.cpp src/io/file_writer.cpp \
				src/packet/icmp_header.cpp src/packet/ipv4_header.cpp src/packet/ipv6_header.cpp \
				src/packet/packet_header.cpp src/packet/payload.cpp src/io/pcap_parser.cpp \
				src/io/stringfile_parser.cpp src/packet/superpacket.cpp src/packet/tcp_header.cpp \
				src/packet/udp_header.cpp src/io/nprint_parser.cpp \
				src/packet/ethernet_header.cpp \
				src/packet/wlan_header.cpp src/packet/radiotap_header.cpp src/packet/dns_header.cpp src/packet/dhcp_header.cpp\
				src/stats.cpp \
				include/conf.hpp include/io/file_parser.hpp include/io/file_writer.hpp \
				include/packet/icmp_header.hpp include/packet/ipv4_header.hpp include/packet/ipv6_header.hpp \
				include/packet/packet_header.hpp include/packet/payload.hpp include/io/pcap_parser.hpp \
				include/io/stringfile_parser.hpp include/packet/superpacket.hpp include/packet/tcp_header.hpp \
				include/packet/udp_header.hpp include/io/nprint_parser.hpp \
				include/packet/ethernet_header.hpp \
				include/packet/wlan_header.hpp include/packet/radiotap_header.hpp include/packet/dns_header.hpp include/packet/dhcp_header.hpp\
				include/stats.hpp

AM_CPPFLAGS = -Iinclude/ -Iinclude/io/ -Iinclude/packet/ -pedantic -Wall -std=gnu++11 $(WRAPPER_CPPFLAGS)
AM_LDFLAGS = $(WRAPPER_LDFLAGS)
