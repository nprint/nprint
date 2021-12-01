# Overview

https://nprint.github.io/nprint.html

# Installation

## Supported Operating Systems

* Debian Linux
* macOS

## Dependencies

* [libpcap](https://www.tcpdump.org/) - Packet sniffing
* [argp](https://www.gnu.org/software/libc/manual/html_node/Argp.html) - Argument parsing

### Install dependencies on Debian:

`sudo apt-get install libpcap-dev`

### Install dependencies on Mac OS

`brew install argp-standalone`

## Installation

1. Download the latest release tar [here](https://github.com/nprint/pcapml/releases/)
2. Extract the tar `tar -xvf [pcapml-version.tar.gz]`
3. `cd [pcapml-directory]`

2. `./configure && make && sudo make install`

## Citing nPrint

```
@inproceedings{10.1145/3460120.3484758,
author = {Holland, Jordan and Schmitt, Paul and Feamster, Nick and Mittal, Prateek},
title = {New Directions in Automated Traffic Analysis},
year = {2021},
isbn = {9781450384544},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3460120.3484758},
doi = {10.1145/3460120.3484758},
pages = {3366–3383},
numpages = {18},
keywords = {machine learning on network traffic, automated traffic analysis, network traffic analysis},
location = {Virtual Event, Republic of Korea},
series = {CCS '21}
}
```
