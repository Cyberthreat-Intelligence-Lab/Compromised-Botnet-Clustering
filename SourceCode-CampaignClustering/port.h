#ifndef PORT_H
#define PORT_H

using namespace std;

struct port{
  u_char protocol;
  u_short portnum;
};

struct Compare{
  bool operator()(const port &lhs, const port &rhs) const{
    if( lhs.protocol > rhs.protocol){
      return false;
    }
    else if(lhs.protocol < rhs.protocol){
      return true;
    }
    else{
      return lhs.portnum < rhs.portnum;
    }
  }
};

#endif
