#ifndef GROUP_H
#define GROUP_H

#include <string>
#include <sstream>
#include <iomanip>
using namespace std;

string make_coord(vector<double> v);

struct Group{
  //Source IP Addresses, indexed in same order as probs
  string IPsources = "";
  //Number of packets per address, correspondin to IPsources
  string packetCounts = "";
  int totalnumPackets = 0;
  //Distribution of ports, formatted to be used in ALGLib AHC
  string probs = "";

  void add_source(string src, int num, vector<double> dist){
    if(IPsources.size() > 0){
      IPsources.insert(IPsources.size(), ",");
    }
    IPsources.insert(IPsources.size(), src);

    if(packetCounts.size() > 0){
      packetCounts.insert(packetCounts.size(), ",");
    }
    packetCounts.insert(packetCounts.size(), to_string(num));

    totalnumPackets += num;
    string s = make_coord(dist);
    if(probs.size() > 0){
      probs.insert(probs.size(), ";");
    }
    probs.insert(probs.size(), s);
  }
};

string make_coord(vector<double> v){
  string t = "[";
  for(unsigned int i = 0; i < v.size(); ++i){
    if(i < 50){
      t += std::to_string(v[i]);
      t += ",";
    }
  }
  t.string::pop_back();
  t += "]";
  return t;
}

#endif
