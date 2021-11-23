# Details
Overview / Original nPrint paper can be found [here](https://nprint.github.io/nprint/).

Detailed usage can be found in the [nPrint wiki](https://github.com/nprint/nprint/wiki).

For a fully automated traffic analysis pipeline, see [nPrintML](https://github.com/nprint/nprintML), which combines nPrint and AutoML.

There will be bugs! Please report any you see.

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
@inproceedings{holland2021nprint,
  title={New directions in automated traffic analysis},
  author={Holland, Jordan and Schmitt, Paul and Feamster, Nick and Mittal, Prateek},
  booktitle={Proceedings of the 2021 ACM SIGSAC Conference on Computer and Communications Security},
  pages={3366--3383},
  year={2021}
}
```
