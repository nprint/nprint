AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = nprint

nprint_SOURCES = src/conf.cpp src/nprint.cpp src/io/file_parser.cpp src/io/file_writer.cpp \
				src/packet/icmp_header.cpp src/packet/ipv4_header.cpp src/packet/ipv6_header.cpp \
				src/packet/packet_header.cpp src/packet/payload.cpp src/io/pcap_parser.cpp \
				src/io/stringfile_parser.cpp src/packet/superpacket.cpp src/packet/tcp_header.cpp \
				src/packet/udp_header.cpp src/io/live_parser.cpp src/io/nprint_parser.cpp \
				include/conf.hpp include/io/file_parser.hpp include/io/file_writer.hpp \
				include/packet/icmp_header.hpp include/packet/ipv4_header.hpp include/packet/ipv6_header.hpp \
				include/packet/packet_header.hpp include/packet/payload.hpp include/io/pcap_parser.hpp \
				include/io/stringfile_parser.hpp include/packet/superpacket.hpp include/packet/tcp_header.hpp \
				include/packet/udp_header.hpp include/io/live_parser.hpp include/io/nprint_parser.hpp

AM_CPPFLAGS = -Iinclude/ -Iinclude/io/ -Iinclude/packet/ -pedantic -Wall -Ofast #-Werror
