# Compromised Host Detection and Botnet Campaign Clustering
## Cyberthreat Intelligence Lab

This project aims to identify infected hosts, retrieve packet-specific features and cluster the identified hosts into botnet campaigns. The included executable documentation can be found with the links below.

#### Preprocessing Misconfigured Traffic from Network Telesceope Data
[Click here to visit the scanpcap documentation](SourceCode-Misconfiguration/README.md)
#### Compromised Host Detection with Scanner-based Features
[Click here to visit the GzPcapBsd documentation](SourceCode-ProbeDetection/README.md)
#### Primary Grouping and Clustering of Identified Botnet Campaigns
[Click here to visit the FeatureDetection documentation](SourceCode-CampaignClustering/README.md)

### Getting Started

The main project folder will contain the *DeviceFingerprinting.sh* shell script. To succesfully run the script, the included 4 executables must be located within the same folder.

The *Device-Fingerprinting.sh* script will contain a number of prompts before executing the program, displaying an advanced help guide to explain necessary arguments and functionality. These can be viewed in the following "Arguments" section.

### Arguments

Device-Fingerprinting requires four arguments, to be entered after initial executation:
```
./Device-Fingerprinting
Input Packet Capture File  : File path for .pcap input data set
Input Number of Packets    : Number of packets to process (0 = entire data set)
Input Starting Position    : Packet to start processing (0 = start of input file)
Input CIDR Size of Network : CIDR size of data set - [/8, /13, /24] networks are supported
```

The *Device-Fingerprinting.sh* script will format each executables output to correctly be used as input to the connected executable. If run individually, the related README will contain the necessary arguments and documentation.

### Libraries

Running the Device-Fingerprinting script requires the following external libraries to be installed:
* Python2.7 - https://www.python.org/download/releases/2.7/
* pip - http://manpages.ubuntu.com/manpages/bionic/man1/pip.1.html
* pandas - https://pypi.org/project/pandas/
* numpy - https://pypi.org/project/numpy/
* scipy - https://pypi.org/project/scipy/

After initial executation, the *Device-Fingerprinting.sh* script will include the option to update and install the required dependencies.

### Usage

The combined programs are resource-intensive, and will utilize large amounts of memory. The executables allow for large datasets to be split and run on the smaller derivatives. A current benchmark relates an 10GB .pcap file to have 70-90 million packets, and requires roughly 16GB of RAM to process.
