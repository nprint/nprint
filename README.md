This repository provides source code for nPrint, described (here)

# Building

` ./configure && make && make install `

# Running

`nPrint --help ` describes many of the options, but we summarize here as well

The transformer takes an infile and outfile. The infile must either be a `.pcap` packet capture, or a `.hexv` file which is a csv file with hex-encoded packets. Zmap can output these, for example. 

outfile will always be a CSV with named columns that can be directly loaded into pandas in python (index column is 0, and is always the **source** IP address. We don't include ethernet headers in any output as they don't really help. Protocols can be added or extended as needed.

* `-4` Include IPv4 headers in the output. (480 columns, 160 for standard header and 320 for padded options)

* `-6` Include IPv6 header in the output. This option is currently untested and only includes the first header, ignoring others if there are a chain.

* `-f` Output all fields of each header as strings instead of bitstrings. For example, the TCP source port would be 80 instead of 1010000

* `-i` Include ICMP headers in output. We always consider an ICMP header as 8 bytee, meaning that headers that include ICMP data would be in the payload, not in the ICMP header.

* `-n=INTEGER` Number of packets to parse if not all in the file. Useful if the PCAP is long and you just want a few packets.

* `-p=INTEGER` Number of bytes of the payload to include in the representation. Completely up to you if and how much of the payload is important for your problem.

* `-q=FILE` File of ip addresses (1 per line) to filter. This filters by SENDER. If a PCAP file has traffic from many hosts, but you're only interested in a few of them, this is useful. This can be combined with the `n` option to grab `n` packets for each host in the file.

* `-r` relative timestamps for PCAP files. This will include a `relative timestamp` column in the output that captures timeseries information for each packet. For example, if three packets were captured at times 0, 5, 8, the relative timestamps would be 0, 5, 3 for each packet.

* `-t` Include TCP headers in the output. (480 columns, 160 for standard header and 320 for padded options)

* `-u` Include UPD headers in the output. Always 64 columns (8 bytes)

* `-w=VALUE`, Each packet must contain a value for every column in the representation, meaning the ICMP columns exist for a TCP packet. By default, these columns will be filled with 0. This may cause confusion for some fields (was the bit a 0, or did the  header not exist?) This option will set all columns to `VALUE` instead of 0.

