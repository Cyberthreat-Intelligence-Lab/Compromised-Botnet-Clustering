//////////////////////////////////////////////////////////////////////////////////
// To compile:
// g++ -std=c++11 -o GzPcapBsd GzPcapBsd.cpp -lpcap `pkg-config --cflags --libs glib-2.0`
// ./GzPcapBsd input output
// ./GzPcapBsd 14.pcap out.pcap
//////////////////////////////////////////////////////////////////////////////////

/* INCLUDES */
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <cstring>
#include <map>
#include <math.h>
#include <list>
#include <time.h>
#include <chrono>
#include <thread>
#include <glib.h>

//#include <sys/socket.h>
//#include <netinet/in.h>

#include <netinet/ether.h>
//#include <net/ethernet.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <errno.h>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <cstdio>
//#include <omp.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>

#include <algorithm>
#include <vector>
#include <dirent.h>

#include <string> 



/* TYPE DEFINITIONS */
GHashTable *flow_table;
pcap_t *pd;
pcap_dumper_t *pdumper;
long unsigned int packet_count;
unsigned int flow_count;
extern int errno;
typedef struct {
  struct timeval start_ts;
  struct timeval end_ts;
  bool finished; 
  u_int32_t src_ip;
  int numPacketInFlow;
} Flow;

using namespace std;

/* Constant Definition */
#define FLOW_MIN_PACKET          100
#define FLOW_MIN_DURATION_MS     60000
#define FLOW_MAX_DELTA_MS        300000


bool hasTimeElapsed(struct timeval start, struct timeval finish, int milliseconds)
{
  struct timeval diff;
  struct timeval delta;
  delta.tv_sec = milliseconds / 1000;
  delta.tv_usec = (milliseconds % 1000) * 1000;
  timersub(&finish, &start, &diff);
  return timercmp(&diff, &delta, >=);
}

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
  struct ip *ip;
  u_int32_t src_ip;

  struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ether_header));
  src_ip = iph->saddr;

  Flow *current_flow = (Flow *)g_hash_table_lookup(flow_table, GUINT_TO_POINTER(src_ip)); // looking up the table to find the src_ip as key
  Flow f =
      {
        start_ts : pkthdr->ts,
        end_ts : pkthdr->ts,
        finished : false,
        src_ip : NULL,
        numPacketInFlow : 1
      };

  bool flow_modified = false;

  if (current_flow != NULL) // src_ip exists in HashTable
  {
    //printf("records found in flow table for this src ip address \n");
    if (current_flow->finished == true)
    {
      //if it is finished then export the packet
      pcap_dump((u_char*)pdumper, pkthdr, (const u_char*)packet);
      current_flow->numPacketInFlow = current_flow->numPacketInFlow+1;

    }
    else if (hasTimeElapsed(current_flow->end_ts, pkthdr->ts, FLOW_MAX_DELTA_MS) == true)
    {
      /// reset the flow -> in other word update the start_ts = current_packet_time and also update numPacketInFlow = 1
      current_flow->start_ts = pkthdr->ts;
      current_flow->end_ts = pkthdr->ts;
      current_flow->numPacketInFlow = 1;
    }
    else if ( (current_flow->numPacketInFlow > FLOW_MIN_PACKET) && (hasTimeElapsed(current_flow->start_ts, current_flow->end_ts, FLOW_MIN_DURATION_MS) == true) )
    {
      // src_ip is a scanner don't need more update. 
      current_flow->finished = true;
      current_flow->numPacketInFlow = 1; // set it to one to start extracting packets
      pcap_dump((u_char*)pdumper, pkthdr, (const u_char*)packet);

      char buffer[100];
      int n;
      char ipsrc[16];
      inet_ntop(AF_INET, &src_ip, ipsrc, 16);
      //printf("#%s\n",ipsrc);
    }
    else
    {
      // just update the flow
      current_flow->finished = false;
      current_flow->end_ts = pkthdr->ts;
      current_flow->numPacketInFlow = current_flow->numPacketInFlow + 1;
    }

  }
  else // src_ip does not exist in the HashTable
  {
    Flow *f = new Flow;
    // create a new record for src_ip in HashTable
    f->src_ip = src_ip;
    f->numPacketInFlow = 1;
    f->finished = false;
    g_hash_table_insert(flow_table, GUINT_TO_POINTER(src_ip), f);
    flow_count++;
  }

  packet_count++;
  if (packet_count % 1000000 == 0)
  {
    printf("# of processed packets = %lu | # of detected scanners = %u  \n", packet_count,flow_count);
  }
}


/* main function */
int main(int argc, char *argv[])
{

  packet_count = 0;
  flow_count = 0;
  char errbuf[PCAP_ERRBUF_SIZE];
  char *pcap_file;
  clock_t begin = clock();
  pcap_t *p;
  flow_table = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
  struct bpf_program filter;
  FILE *fp;

  GString *InPath = g_string_new(argv[1]);
  GString *outPath = g_string_new(argv[2]);

  if (argc < 3)
  {
    printf("ERROR: number of input arguments should be 2\n");
    exit(0);
  }
  else if (argc == 3)
  { 
    // Default mode which export packets originated by scanners 
  }
  else if (argc >= 4)
  {
    printf("ERROR: too many inputs, number of input arguments should be 2\n");
    exit(0);
  }

  
  ///  create, open a pcap file
  /* create handler to write to output pcap*/
  pd =  pcap_open_dead(DLT_EN10MB, 65535);
  pdumper = pcap_dump_open(pd, outPath->str);
  /////////////////

  fp = fopen(InPath->str, "r");
  p = pcap_fopen_offline(fp, errbuf);
  if (p == NULL)
  {
    fprintf(stderr, "Error reading pcap file: %s\n", errbuf);
    getchar();
    return 2;
  }

  // only capture scan related packets (NO backscatters)
  char filter_exp[] = " ((tcp[tcpflags]  != (tcp-syn|tcp-ack)) && (tcp[tcpflags]  != (tcp-rst|tcp-ack)) && (tcp[tcpflags]  != (tcp-rst))) || ( (icmp[icmptype] != (icmp-echoreply)) && (icmp[icmptype] != (icmp-tstampreply)) && (icmp[icmptype] != (icmp-unreach)) && (icmp[icmptype] != (icmp-timxceed)) ) || udp";

  if (pcap_compile(p, &filter, filter_exp, 0, 0) == -1)
  {
    printf("Bad filter - %s\n", pcap_geterr(p));
    return 2;
  }
  if (pcap_setfilter(p, &filter) == -1)
  {
    printf("Error setting filter - %s\n", pcap_geterr(p));
    return 2;
  }

  printf("Probe Detection Started ...\n");
  pcap_loop(p, -1, packetHandler, NULL);
  pcap_close(p);
  pcap_close(pd);
  pcap_dump_close(pdumper);
  printf("Probe Detection is DONE.\n");
}