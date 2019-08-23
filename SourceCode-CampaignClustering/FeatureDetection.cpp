#include <pcap.h>
#include <iostream>
#include <fstream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "Flow.h"
#include "Group.h"

void packetHandler(u_char * args, const struct pcap_pkthdr* pkthdr,
const u_char * packet);

const struct ether_header * ethernetHeader;
const struct ip * ipHeader;
const struct tcphdr * tcp;
const struct udphdr * udp;
char sourceIP[INET_ADDRSTRLEN];
char destIP[INET_ADDRSTRLEN];

int totalPacketsRead = 0;
std::string srcIP;
std::string dstIP;

typedef map<std::string, Flow*> flowMap;

int main(int argc, char * argv[]){
  if(argc != 2){
    cout << "ERROR: Takes one command line argument" << endl;
    return 1;
  }

  std::string file = argv[1];
  std::string extension = file.substr(file.length() - 5, 5);

  if(extension.compare(".pcap")){
    cout << "ERROR: Please use valid .pcap file" << endl;
    return 1;
  }

  pcap_t *descr;
  char errbuf[PCAP_ERRBUF_SIZE];

  // open file for offline capture
  descr = pcap_open_offline(argv[1], errbuf);
  if(descr == NULL) {
    std::cout << "pcap_open_offline() failed: " << errbuf << std::endl;
    return 1;
  }


  flowMap * features = new flowMap();

  std::cout << "Processing packets..." << endl;
  // start packet analysis loop
  if(pcap_loop(descr, 0, packetHandler,
    reinterpret_cast<u_char*>(features)) < 0) {
    std::cout << "pcap_loop() failed: " << pcap_geterr(descr);
    return 1;
  }
  std::cout << "Packet processing complete!" << endl << endl;

  flowMap::const_iterator it;

  for(it = features->begin(); it != features->end(); ++it){
    (it->second)->calc_ARR();
    (it->second)->calc_flag();
    (it->second)->calc_probs();
    (it->second)->clean_ports();
  }

  std::cout << "Number of unique sources:\t" << features->size() << endl;
  std::cout << "Number of packets processed:\t" << totalPacketsRead << endl;
  std::cout << "Features structure complete" << endl << endl;

  map<Flow, Group, FlowCompare> classifier;

  std::cout << "Creating primary groupings..." << endl;
  //iterate through features and insert IP sources into groups
  for(it = features->begin(); it != features->end(); ++it){
    if((it->second)->portCounts.size() != 0){
      classifier[*(it->second)].add_source(it->first,
        (it->second)->numPackets, (it->second)->probIP);
    }
  }

  std::cout << "Primary grouping complete!" << endl;
  std::cout << "Number of unique groups:\t" << classifier.size() << endl << endl;

  map<Flow, Group, Compare>::iterator classIt;
  classIt = classifier.begin();

  ofstream midfile;
  midfile.open("PrimaryGroupings.txt");
  for(classIt = classifier.begin(); classIt != classifier.end(); ++classIt){
    if(classIt->second.totalnumPackets >= 500){
      midfile << classIt->second.IPsources << endl;
      midfile << classIt->second.packetCounts << endl;
      midfile << classIt->first.ports_to_string() << endl;
      midfile << classIt->first.flag << endl;
      midfile << classIt->first.ARR << endl;
      midfile << classIt->second.probs << endl;
    }
  }

  midfile.close();
  for(it = features->begin(); it != features->end(); ++it){
      delete (it->second);
  }

  std::cout << "Data Cleaned" << endl;

  return 0;

}

void packetHandler(u_char * args, const struct pcap_pkthdr* pkthdr,
const u_char * packet){

  //inputs to add_packet()
  port destPort;
  bool flag_in = 0;

  //casting the user paramter back to a map
  flowMap * features = reinterpret_cast<flowMap*>(args);

  ethernetHeader = (struct ether_header*) packet;
  if(ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP){

    ipHeader = (struct ip*) (packet + sizeof(struct ether_header));
    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);

    destPort.protocol = ipHeader->ip_p;

    //Next, check TCP and UDP, getting destPort and
    //flag. Then outside of this if statement, check
    //if this is the first of an IP source, the first
    //of a flow, and add the packet appropriately
    if(ipHeader->ip_p == IPPROTO_TCP){
      tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) +
      sizeof(struct ip));
      destPort.portnum = ntohs(tcp->dest);

      if(tcp->th_seq == ipHeader->ip_dst.s_addr){
        flag_in = 1;
      }
    }
    else if(ipHeader->ip_p == IPPROTO_UDP || ipHeader->ip_p == IPPROTO_ICMP){
      udp = (struct udphdr*)(packet + sizeof(struct ether_header) +
      sizeof(struct ip));
      destPort.portnum = ntohs(udp->dest);
    }
  }
  else{
    return;
  }
  inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
  srcIP = sourceIP;
  dstIP = destIP;

  flowMap::const_iterator it;
  it = features->find(srcIP);

  //Checks if the source IP is new
  if(it == features->end()){
    Flow *f = new Flow(destPort, dstIP, flag_in);
    (*features)[srcIP] = f;
  }
  //Otherwise, add the packet to the current flow
  else{
    ((*features)[srcIP])->add_packet(destPort, dstIP, flag_in);
  }
  ++totalPacketsRead;
  if(totalPacketsRead % 5000000 == 0){
    std::cout << "Packets read: " << totalPacketsRead << endl;
  }
}
