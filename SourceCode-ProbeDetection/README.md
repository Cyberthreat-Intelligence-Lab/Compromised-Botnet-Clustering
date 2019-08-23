# Compromised Host Detection with Scanner-based Features

This project includes the executable GzPcapBsd.o and its source code. With the goal of identifying compromised host addresses partaking in Internet scanning activities, the executable will process an input packet capture (.pcap) data set and outputs an attributed .pcap file. This executable has been compiled in C++ for Debian and Ubuntu Linux System and can be run from Terminal.


## Getting Started

The precompiled executable GzPcapBsd.o is ready to use from the Terminal of any Debian or Ubuntu Linux operating system. Simply download the executable, and use the terminal command ./GzPcapBsd.o, including its argument, to begin processing your dataset. See the following section "Arguments" for more detailed information regarding the executable's arguments.

The source code is compiled in C++ with the g++ compiler and requires additional libraries. See the following section "Libraries and Compiling" for more detailed information on installing these additions. The following section "Source Code" contains detailed information regarding each file used to create this program.

### Arguments

GzPcapBsd.o requires two arguments when executed:
```
./GzPcapBsd.o <InFile> <OutFile>
InFile     : File path for .pcap input data set
OutFile    : File path to print .pcap misconfigured packets
```

### Libraries and Compiling

Compiling the source code requires the following external libraries to be installed:
* tcpdump/libpcap - https://www.tcpdump.org/
* libglib2.0-dev - https://packages.ubuntu.com/xenial/libglib2.0-dev

An example command for compiling with g++ and then linking the files:
```
g++ -std=c++11 -o GzPcapBsd GzPcapBsd.cpp -lpcap `pkg-config --cflags --libs glib-2.0`
```

### Source Code

The scanpcap project currently includes a singular source file:
* **GzPcapBsd.o** - source file containing headers and primary functionality
