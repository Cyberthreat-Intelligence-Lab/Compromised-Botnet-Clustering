# Primary Grouping and Clustering of Identified Botnet Campaigns

This project includes the executable FeatureDetection.o and its source code. Additionally, the Clusterizer.py python script is included. With an input packet capture file (.pcap), the executable will process and determine a key set containing the grouping of related IP addresses. This output is then leveraged by Clusterizer.py, containing a clustering algorithm used to group campaigns from within their related key set. The executable has been compiled in C++ for Debian and Ubuntu Linux Systems and can be run from terminal. The python script is written for Python 2.7 and can be run from the terminal.

## Getting Started

The precompiled executable FeatureDetection.o is ready to use from the terminal of any Debian and Ubuntu Linux operation system. Simply download the executable and use the terminal command ./FeatureDetection.o, including arguments, to begin processing your dataset. See the following section "Arguments" for more detailed information regarding the executable's arguments.

The source code is compiled in C++ with the g++ compiler and requires additional libraries. See the following section "Libraries and Compiling" for more detailed information on installing these additions. The following section "Source Code" contains detailed information regarding each file used to create this program.

The python script Clusterizer.o is ready to use from the terminal of any Debian and Ubuntu Linux operating system. Simply download the python script and use the terminal command python to begin clustering your dataset. See the following section "Arguments" for detailed information regarding the script's file inputs.

The python script is run using Python 2.7 and has additional dependencies. See the following section "Libraries and Compiling" for more detailed information on installing these additions.

### Arguments

FeatureDetection.o requires one argument when executed:

```
./FeatureDetection.o <InFile>
InFile :  File path for .pcap input data set
```

Clusterizer.py requires PrimaryGroupings.txt to be in the file path. Executing FeatureDetection.o outputs this file, as FeatureDetection.o and Clusterizer.py are meant to be used in sequence.

### Libraries and Compiling

Compiling the source code for FeatureDetection.o requires the following external library to be installed:
* tcpdump/libpcap - https://www.tcpdump.org/

An example command for compiling with g++ and linking the libraries:

```
g++ FeatureDetection.cpp -o FeatureDetection.o -lpcap
```
Running the Clusterizer.py script requires the following external libraries to be installed:
* Python2.7 - https://www.python.org/download/releases/2.7/
* pip - http://manpages.ubuntu.com/manpages/bionic/man1/pip.1.html
* pandas - https://pypi.org/project/pandas/
* numpy - https://pypi.org/project/numpy/
* scipy - https://pypi.org/project/scipy/

### Source

The FeatureDetection project is currently split into one .cpp file and three .h files:
* **Flow.h -** header file containing the Flow class and FlowCompare comparator
* **Group.h -** header file containing the Group class and helper functions
* **port.h -** header file containing the port data structure and Compare comparator
* **FeatureDetection.cpp -** source file containing main program driver and functionality

The Clusterizer project is currently contained in one .py file:
* **Clusterizer.py -** python script containing main program diver and functionality
