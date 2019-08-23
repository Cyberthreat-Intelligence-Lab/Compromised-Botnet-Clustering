printf "Welcome to the Cyberthreat Intelligence Lab's Compromised Host Detection and Botnet Campaign Clustering Program!\n"
time=$(date +"%T")
printf "Current Time: "%s"\n" $time

printf "\nWould you like to view the help display? Enter y/n: "
read help

if [ $help == 'y' ]
then
	printf "\n"
	printf ""%s"The included executables will sanitize, process and infer infected host IP addresses and cluster botnets.\n" '--'
	printf ""%s"Due to memory and processing time limitations, the executables allow for large datasets to be split.\n" '--'
	printf ""%s"Benchmark: 16GB of RAM is required to process 8-10GB of data, estimated to equal 80-90 million packets.\n" '--'
	printf ""%s"\nRequirements:\n" '--'
	printf ""%s"Python v2.7 with pandas, numpy and scipy installed.\n" '---'
	printf ""%s"libglib2.0-dev and libpcap-dev.\n" '---'

	printf "\nThe following options can be updated within the advanced options page.\n"
	printf "<Input Packet Capture File>: input packet capture file dataset, include the '.pcap' extension.\n"
	printf "<Input Number of Packets>: number of packets to be processed, '0' denotes processing the entire dataset.\n"
	printf "<Input Starting Position>: packet location to be processed, '0' denotes processing from the beginning of the dataset.\n"
	printf "<Input CIDR Size of Network>: CIDR of a network, include the '/' before network size.\n"

fi

printf "\nWould you like to view the default configuration? Enter y/n: "
read default

if [ $default == 'y' ]
then
printf "\nDefault Configuration:\n"
	printf "Packet Capture File: "%s"\n" 'input.pcap'
	printf "Number of Packets: "%s"\n" '0 (entire dataset)'
	printf "Starting Position: "%s"\n" '0 (start from beginning)'
	printf "CIDR Size: "%s"\n" '/8'
fi

printf "\nWould you like to update and install dependencies? Enter y/n: "
read python

if [ $python == 'y' ]
then
	sudo apt-get update
	sudo apt-get install libpcap-dev libglib2.0-dev
	sudo apt-get install python2.7  python-pip
	pip install pandas
	pip install scipy
	printf "\nDependencies Installed!\n"
fi

printf "\nWould you like to enter advanced options? Enter y/n: "
read options

if [ $options == 'y' ]
then
	printf "\n"
	printf "Input Packet Capture File: "
	read firstdataset
	printf "Input Number of Packets: "
	read packetcount
	printf "Input Starting Position: "
	read startpos
	printf "Input CIDR Size of Network, Include the [/]: "
	read cidr
else
	printf "\nUsing Default Configuration!\n"
	firstdataset=input.pcap
	packetcount=0
	startpos=0
	cidr=/8
fi

totalstart=$(date +"%s")
printf "\n%s" "----------------------------------------"
start=$(date +"%s")
printf "\nStarting Misconfiguration Cleansing\n"
sudo ./scanpcap.o $packetcount $startpos $cidr $firstdataset inferredmisconfigured.pcap inferredmalicious.pcap
end=$(date +"%s")
runtime=$((end-start))
printf "Step Complete! Step 1 Running Time: "%s" seconds\n" $runtime
printf "%s\n" "----------------------------------------"


printf "\n%s" "----------------------------------------"
start2=$(date +"%s")
printf "\nStarting Probe Detection\n"
sudo ./GzPcapBsd.o inferredmalicious.pcap inferredprobes.pcap
end2=$(date +"%s")
runtime2=$((end2-start2))
printf "Step Complete! Step 2 Running Time: "%s" seconds\n" $runtime2
printf "%s\n" "----------------------------------------"

printf "\n%s" "----------------------------------------"
start3=$(date +"%s")
printf "\nStarting Compromised Device Fingerprinting\n"
sudo ./FeatureDetection.o inferredprobes.pcap
end3=$(date +"%s")
runtime3=$((end3-start3))
printf "Step Complete! Step 3 Running Time: "%s" seconds\n" $runtime3
printf "%s\n" "----------------------------------------"

printf "\n%s" "----------------------------------------"
start4=$(date +"%s")
printf "\nStarting Botnet Clustering\n"
sudo python ./Clusterizer.py
end4=$(date +"%s")
runtime4=$((end4-start4))
printf "Step Complete! Step 4 Running Time: "%s" seconds\n" $runtime4
printf "%s\n" "----------------------------------------"

printf "\n%s" "----------------------------------------"
totalend=$(date +"%s")
totaltime=$((totalend-totalstart))
sudo sort -t',' -k5,5gr campaigns_table.csv | sudo tee final_output.csv 1>/dev/null
sudo sed -i 1i"id,Ports,Flag,ARR,# of Bots,Distribution,# of Packets" final_output.csv
printf "\nAlgorithms Complete! All Steps Successful, Final Output -> final_output.csv\n"
printf "Total Running Time: "%s" seconds\n" $totaltime
printf "%s\n" "----------------------------------------"
