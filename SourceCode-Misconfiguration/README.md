# Preprocessing Misconfigured Traffic from Network Telescope Data

This project includes the executable scanpcap.o and its source code. With the goal of
cleansing packet capture (.pcap) data sets and removing misconfigured traffic, the executable processes a .pcap
data set and outputs two new .pcap files. The first output file contains all packets calculated to be misconfigured, while the second file contains all packets calculated to be malicious. This executable has been compiled in C++ for Debian and Ubuntu Linux Systems and can be run from Terminal.

## Getting Started

The precompiled executable scanpcap.o is ready to use from the Terminal of any Debian or Ubuntu Linux operating system. Simply download the executable, and use the terminal command ./scanpcap.o, including its arguments, to begin processing your dataset. See the following section "Arguments" for more detailed information regarding the executable's arguments.

The source code is compiled in C++ with the g++ compiler and requires additional libraries. See the following section "Libraries and Compiling" for more detailed information on installing these additions. The following section "Source Code" contains detailed information regarding each file used to create this program.

### Arguments

scanpcap.o requires six arguments when executed:
```
./scanpcap.o <NumPackets> <StartPos> <CIDR> <InFile> <OutFile1> <OutFile2>
NumPackets : Number of packets to process (0 = entire data set)
StartPos   : Packet to start processing (0 = start of input file)
CIDR       : CIDR size of data set - [/8, /13, /24] networks are supported
InFile     : File path for .pcap input data set
OutFile1   : File path to print .pcap misconfigured packets
OutFile2   : File path to print .pcap malicious packets
```

Executing the program with a "?" or "help" option will display basic argument information:
```
./scanpcap.o ?  or ./scanpcap.o help
./scanpcap.o -? or ./scanpcap.o -help
```

### Libraries and Compiling

Compiling the source code requires the following external libraries to be installed:
* tcpdump/libpcap - https://www.tcpdump.org/
* PcapPlusPlus - https://seladb.github.io/PcapPlusPlus-Doc/

An example command for compiling with g++ and then linking the files:
```
g++ scanpcap.cpp initialize.cpp output.cpp -o scanpcap.o -lpcap -lPcap++ -lPacket++ -lCommon++
```

### Source Code

The scanpcap project is currently split into three .cpp files and two .h files:
* **include.h -** header file containing all external and local libraries
* **scanpcap.h -** header file containing primary class and function declarations
* **initialize.cpp -** source file containing class function definitions
* **output.cpp -** source file containing class function definitions
* **scanpcap.cpp -** source file containing main program driver
