#include "router.h"
#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <arpa/inet.h>
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
#define N 9
#define M 3277

class Unit{
public:
  RoutingTableEntry routingTableEntry;
  uint32_t next;
  bool isDeleted;
};

std::vector<Unit> vec(1);
uint32_t arr[N][M];

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 *
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
  if(!insert){
      std::vector<Unit>::iterator iter ;
      for(iter=vec.begin(); iter!=vec.end();){
          uint32_t addr = ntohl(entry.addr)>>(32-entry.len);
          bool checkAddr = (*iter).routingTableEntry.addr == addr;
          bool checkLength = (*iter).routingTableEntry.len == entry.len;
          if(checkAddr && checkLength){ iter = vec.erase(iter); (*iter).isDeleted = true; }
          else { iter++; }
      }
  }else{
    int n = (entry.len-1)>>2;
    int m = (ntohl(entry.addr)>>(32-(((n)<<2)+1)))%M;
    uint32_t addr = ntohl(entry.addr)>>(32-entry.len);

    bool isFound = false;
    int j=arr[n][m];
    while(j){
        if(vec[j].routingTableEntry.addr == addr && vec[j].routingTableEntry.len == entry.len){
            RoutingTableEntry e = (RoutingTableEntry){addr,entry.len, entry.if_index, entry.nexthop, entry.metric, entry.timestamp};
            vec[j] = (Unit){e,vec[j].next,false};
            isFound = true;
        }
        j=vec[j].next;
    }
    if(isFound){
        return;
    } else {
      RoutingTableEntry e = (RoutingTableEntry){addr,entry.len, entry.if_index, entry.nexthop, entry.metric, entry.timestamp};
      Unit unit = (Unit) {e,arr[n][m],false};
      arr[n][m] = vec.size();
      vec.push_back(unit);
    }
  }

}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @param metric 如果查询到目标，把表项的 metric 写入
 * @param timestamp 如果查询到目标，把表项的 timestamp 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric, uint32_t *timestamp) {
  *nexthop = 0;
  *if_index = 0;
  *metric = 0;
  *timestamp = 0;
  for(uint32_t i=32; i>=8; i-=4){
    uint32_t mask=0, index=0, n=(i-1)>>2, m=(ntohl(addr)>>(35-i))%M;
    if (arr[n][m]) {
      for (uint32_t j=arr[n][m]; j; j=vec[j].next) {
          bool check0=!vec[j].isDeleted && vec[j].routingTableEntry.addr==(ntohl(addr)>>(32-i)) && vec[j].routingTableEntry.len==i && mask<j;
          bool check1=!vec[j].isDeleted && vec[j].routingTableEntry.addr==(ntohl(addr)>>(33-i)) && vec[j].routingTableEntry.len==i-1 && mask<i-1;
          bool check2=!vec[j].isDeleted && vec[j].routingTableEntry.addr==(ntohl(addr)>>(34-i)) && vec[j].routingTableEntry.len==i-2 && mask<i-2;
          bool check3=!vec[j].isDeleted && vec[j].routingTableEntry.addr==(ntohl(addr)>>(35-i)) && vec[j].routingTableEntry.len==i-3 && mask<i-3;
          if(check0){
                *nexthop = vec[j].routingTableEntry.nexthop;
                *if_index = vec[j].routingTableEntry.if_index;
                *metric = vec[index].routingTableEntry.metric;
                *timestamp = vec[index].routingTableEntry.timestamp;
                return true;
          }
          if(check1){ mask=j-1; index=j; }
          if(check2){ mask=j-2; index=j; }
          if(check3){ mask=j-3; index=j; }
      }
      if(mask){
         *nexthop = vec[index].routingTableEntry.nexthop;
         *if_index = vec[index].routingTableEntry.if_index;
         *metric = vec[index].routingTableEntry.metric;
         *timestamp = vec[index].routingTableEntry.timestamp;
         return true;
      }
    }
  }
  return false;
}

void fillResp(RipPacket *resp, int command) {
  (*resp).command = command;
  int size = 0;
  std::vector<Unit>::iterator iter ;
  for(iter=vec.begin(); iter!=vec.end(); iter++){
    if((*iter).isDeleted == false) {
      (*resp).entries[size].addr = (*iter).routingTableEntry.addr;
      (*resp).entries[size].mask = 0;
      (*resp).entries[size].nexthop = 0;
      (*resp).entries[size].metric = (*iter).routingTableEntry.metric;
      size += 1;
    }
  }
  (*resp).numEntries = size;
}
