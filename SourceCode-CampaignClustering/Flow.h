#ifndef FLOW_H
#define FLOW_H

#include <utility>
#include <iostream>
#include <map>
#include <set>
#include <vector>
#include "port.h"
#include <string>
#include <math.h>

using namespace std;

// Flow class
class Flow{
public:
  int numPackets;
  int flagRunningTotal;
  //set<port, Compare> ports;
  map<port, int, Compare> portCounts;
  set<string> destIPs;
  vector<double> probIP;
  int ARR;
  bool flag;
  bool rnd = false;


  Flow() : numPackets(0), flagRunningTotal(0), portCounts({}),
  destIPs({}), probIP({}), flag(0) {}

  Flow(port destPort, string dest_addr,
  int flag_in) : numPackets(1), flagRunningTotal(flag_in),
  portCounts({{destPort, 1}}), destIPs({dest_addr}),
  probIP({}), ARR(0), flag(0) {}

  void add_packet(port destPort,
  string dest_addr, bool flag_in){
    ++numPackets;
    //ports.insert(destPort);
    ++(portCounts[destPort]);
    destIPs.insert(dest_addr);
    //flag = flag || flag_in;
    flagRunningTotal += flag_in; // What do when given non tcp packet?
  }

  //For flow comparison:
  bool operator==(const Flow &rhs) const{
    if(flag != rhs.flag){
      std::cout << "Flag test failed" << endl;
      return false;
    }
    if(rnd != rhs.rnd){
      std::cout << "Rnd test failed" << endl;
      return false;
    }
    if( ARR != rhs.ARR){
      std::cout << "ARR test failed" << endl;
      return false;
    }
    if(portCounts.size() != rhs.portCounts.size()){
      std::cout << "Port test 1 failed" << endl;
      return false;
    }
    std::map<port, int>::const_iterator it1 = portCounts.begin();
    std::map<port, int>::const_iterator it2 = rhs.portCounts.begin();
    while((it1 != portCounts.end()) && (it2 != rhs.portCounts.end())){
      if(((it1->first).protocol != (it2->first).protocol) ||
          ((it1->first).portnum != (it2->first).portnum)){
        std::cout << "Port test 2 failed" << endl;
        return false;
      }
      ++it1;
      ++it2;
    }
    return true;
  }

  void calc_ARR(){
    double temp = (double) numPackets / destIPs.size();
    ARR = roundf(temp);
  }

  void calc_flag(){
    double num = flagRunningTotal / (double) numPackets;
    flag = num > .95;
  }

  void calc_probs(){
    for(auto& pair : portCounts){
      probIP.push_back((double) pair.second / (double) numPackets);
    }
  }

  void clean_ports(){
    std::map<port, int>::iterator it = portCounts.begin();
    int i = 0;
    double thresh = .002;
    int init_size = portCounts.size();
    if(init_size > 50){
      thresh = .001;
    }
    while(it != portCounts.end()){
      if((it->first).protocol == IPPROTO_ICMP){
        thresh = 0;
      }
      if(probIP[i] < thresh){
        it = portCounts.erase(it);
        probIP.erase(probIP.begin() + i);
      }
      else{
        ++it;
        ++i;
      }
      thresh = .002;
      if(init_size > 50){
        thresh = .001;
      }
    }
    double totalProb = 0;
    for(unsigned int i = 0; i < probIP.size(); ++i){
      totalProb += probIP[i];
    }
    if(totalProb != 1){
      rnd = true;
    }
  }

  string ports_to_string() const{
    string s = "[";
    int i = 0;
    for(auto& pair : portCounts){
      if(i < 50){
        string q = "";
        if(pair.first.protocol == IPPROTO_UDP){
          q += "UDP:";
        }
        else if(pair.first.protocol == IPPROTO_ICMP){
          q += "ICMP:";
        }
        else{
          q += "TCP:";
        }
        q += to_string(pair.first.portnum);
        q += ",";
        s += q;
      }
      ++i;
    }
    s.string::pop_back();
    if(rnd){
      s += "+rnd";
    }
    s += "]";
    return s;
  }
};

struct FlowCompare{
  bool operator()(const Flow &lhs, const Flow &rhs) const{
    if(!lhs.flag && rhs.flag){
      return true;
    }
    if(lhs.flag && !rhs.flag){
      return false;
    }
    if(!lhs.rnd && rhs.rnd){
      return true;
    }
    if(lhs.rnd && !rhs.rnd){
      return false;
    }
    if(lhs.ARR < rhs.ARR){
      return true;
    }
    if(lhs.ARR > rhs.ARR){
      return false;
    }
    if(lhs.portCounts.size() < rhs.portCounts.size()){
      return true;
    }
    if(lhs.portCounts.size() > rhs.portCounts.size()){
      return false;
    }
    std::map<port, int>::const_iterator it1 = lhs.portCounts.begin();
    std::map<port, int>::const_iterator it2 = rhs.portCounts.begin();
    while((it1 != lhs.portCounts.end()) && (it2 != rhs.portCounts.end())){
      if((it1->first).protocol < (it2->first).protocol){
        return true;
      }
      if((it1->first).protocol == (it2->first).protocol){
        if((it1->first).portnum < (it2->first).portnum){
          return true;
        }
        if((it1->first).portnum >= (it2->first).portnum){
          return false;
        }
      }
      ++it1;
      ++it2;
    }
    return false;
  }
};

#endif
