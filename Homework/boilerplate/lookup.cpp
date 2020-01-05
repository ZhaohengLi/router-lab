#include "../boilerplate/router.h"
#include "../boilerplate/rip.h"
#include <stdint.h>
#include <stdlib.h>
#include<vector>
#include<stdio.h>
using namespace std;

vector<RoutingTableEntry> routingTable;

void update(bool insert, RoutingTableEntry entry) {
  auto iter = routingTable.cbegin();
  while(iter != routingTable.cend()){
    RoutingTableEntry getTable = *iter;
    if(getTable.addr == entry.addr && getTable.len == entry.len){
      routingTable.erase(iter);
      if(insert)
        break;
      else
        return;
      }
    iter++;
  }
  if(insert)
    routingTable.insert(routingTable.end(), entry);
}

bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  *nexthop = 0;
  *if_index = 0;
  uint32_t lenBound = 0;

  auto iter = routingTable.cbegin();
  while(iter != routingTable.cend()){
    RoutingTableEntry getTable = *iter;

    uint32_t addrRes = getTable.addr ^ addr;
    addrRes = addrRes << (32-getTable.len);
    if(addrRes == 0 && getTable.len > lenBound){
      lenBound = getTable.len;
      *nexthop = getTable.nexthop;
      *if_index = getTable.if_index;
    }
    iter++;
  }
  if(lenBound != 0)
    return true;
  else
    return false;
}

void response(RipPacket *resp, uint32_t if_index){
  resp->command = 0x2;
  int entry_num = 0;
  for (uint32_t i = 0; i < routingTable.size(); i++) {
    if(routingTable[i].if_index == if_index) continue; //如果同一个端口 则不加入这条路由表条目
    uint32_t mask =  ((0x1 << routingTable[i].len) - 1);
    uint32_t correct_mask = 0;
    if(routingTable[i].len == 32)
      correct_mask = 0xffffffff;
    else{
      for(int i=0;i<4;i++)
        correct_mask += ((mask >> (i*8)) & 0xff) << ((3-i) * 8);
    }
    RipEntry entry = {
        .addr = routingTable[i].addr,
        .mask = mask,
        .nexthop = routingTable[i].nexthop,
        .metric = routingTable[i].metric
    };
    resp->entries[entry_num++] = entry;
  }
  resp->numEntries = entry_num;
}

void response(RipPacket *resp, uint32_t if_index, int table_index){
  resp->command = 0x2;
  int entry_num = 0;
  for (uint32_t i = table_index; i < routingTable.size() && i < table_index+25; i++) {
    if(routingTable[i].if_index == if_index) continue;
    uint32_t mask =  ((0x1 << routingTable[i].len) - 1);
    uint32_t correct_mask = 0;
    if(routingTable[i].len == 32)
      correct_mask = 0xffffffff;
    else{
      for(int i=0;i<4;i++)
        correct_mask += ((mask >> (i*8)) & 0xff) << ((3-i) * 8);
    }
    RipEntry entry = {
        .addr = routingTable[i].addr,
        .mask = mask,
        .nexthop = routingTable[i].nexthop,
        .metric = routingTable[i].metric
    };
    resp->entries[entry_num++] = entry;
  }
  resp->numEntries = entry_num;
}


int getRoutingTableSize(){
  return routingTable.size();
}

void update(RoutingTableEntry entry) {
  auto iter = routingTable.cbegin();
  bool update_flag = true;
  while(iter != routingTable.cend()){
    RoutingTableEntry getTable = *iter;
    if(getTable.addr == entry.addr && getTable.len == entry.len){
      update_flag = false;
      if(entry.if_index == getTable.if_index || entry.metric <= getTable.metric){
        if (getTable.nexthop != 0) {
          routingTable.erase(iter);
          update_flag = true;
        }
      }
      break;
    }
    iter++;
  }
  if(update_flag)
    routingTable.insert(routingTable.end(), entry);
}

void printTable(){
  printf("RIP Table of the router now:\n");
  for(int i = 0 ; i < routingTable.size() ; i++){
    auto entry = routingTable[i];
    uint32_t dest[4];
    uint32_t nexthop[4];
    for(int i = 0 ; i < 4 ; i++){
      dest[i] = (entry.addr >> (i * 8)) & 0xff;
      nexthop[i] = (entry.nexthop >> (i * 8)) & 0xff;
    }
    printf("%u.%u.%u.%u via %u.%u.%u.%u with length: %u interface: %u metric: %u\n", dest[0], dest[1], dest[2], dest[3], nexthop[0], nexthop[1],nexthop[2],nexthop[3], entry.len, entry.if_index, entry.metric);
  }
}
