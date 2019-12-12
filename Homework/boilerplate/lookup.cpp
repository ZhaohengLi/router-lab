#include "../boilerplate/router.h"
#include "../boilerplate/rip.h"
#include <stdint.h>
#include <stdlib.h>
#include<vector>
#include<stdio.h>
using namespace std;

vector<RoutingTableEntry> routingTable;

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 *
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
    // TODO:
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

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  // TODO:
  *nexthop = 0;
  *if_index = 0;
  uint32_t lenBound = 0;

  auto iter = routingTable.cbegin();
  // printf("trying to find addr: %08X\n", addr);
  while(iter != routingTable.cend()){
    RoutingTableEntry getTable = *iter;
    // uint32_t mask = -1;
    // if(getTable.len < 32)
    //   mask = (1 << getTable.len) - 1;
    uint32_t addrRes = getTable.addr ^ addr;
    // auto token = addrRes & mask;
    addrRes = addrRes << (32-getTable.len);
    if(addrRes == 0 && getTable.len > lenBound){
      // printf("Found!\n");
      // printf("matched addr: %08X, len: %d, calculated mask: %08X, addrRes: %08X", getTable.addr, getTable.len, mask, addrRes);
      lenBound = getTable.len;
      *nexthop = getTable.nexthop;
      *if_index = getTable.if_index;
    }
    iter++;
  }
  // printf("Result len is: %d\n", lenBound);
  if(lenBound != 0)
    return true;
  else
    return false;
}

void response(RipPacket *resp, uint32_t if_index){
  resp->command = 0x2;
  int entry_num = 0;
  for (uint32_t i = 0; i < routingTable.size(); i++) {
    if(routingTable[i].if_index == if_index)
      continue;
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

void update(RoutingTableEntry entry) {
    // TODO:
  auto iter = routingTable.cbegin();
  bool update_flag = true;
  while(iter != routingTable.cend()){
    RoutingTableEntry getTable = *iter;
    if(getTable.addr == entry.addr && getTable.len == entry.len){
      update_flag = false;
      if(entry.if_index == getTable.if_index || entry.metric + 1 <= getTable.metric){
        routingTable.erase(iter);
        update_flag = true;
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
    printf("%u.%u.%u.%u via %u.%u.%u.%u with length %u through interface %u with metric %\n", dest[0], dest[1], dest[2], dest[3], nexthop[0], nexthop[1],nexthop[2],nexthop[3], entry.len, entry.if_index, entry.metric);
  }
}
