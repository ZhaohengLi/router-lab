#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include "rip.h"
#include <arpa/inet.h>

using std::vector;

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
    for (int i = 0; i < routingTable.size(); i++) {
        if (routingTable[i].addr == entry.addr && routingTable[i].len == entry.len) {
            if (insert) {
                routingTable[i] = entry;
            }
            else {
                routingTable[i] = routingTable[routingTable.size() - 1];
                routingTable.pop_back();
            }
            return;
        }
    }
    routingTable.push_back(entry);
}

void rip_update(RoutingTableEntry entry) {
    for (int i = 0; i < routingTable.size(); i++) {
        if (routingTable[i].addr == entry.addr && routingTable[i].len == entry.len) {
            if (entry.metric + 1 <= routingTable[i].metric) {
            routingTable[i] = entry;
            routingTable[i].metric++;
            }
            return;
        }
    }
    routingTable.push_back(entry);
}
/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
    *nexthop = 0;
    *if_index = 0;
    uint32_t max_len = 0;
    for (int i = 0; i < routingTable.size(); i++) {
        uint32_t ans = addr ^ routingTable[i].addr;
        ans <<= (32 - routingTable[i].len);
        if (ans == 0) {
            if (max_len < routingTable[i].len) {
                *nexthop = routingTable[i].nexthop;
                *if_index = routingTable[i].if_index;
                max_len = routingTable[i].len;
            }
        }
    }
    if (max_len != 0) {
        return true;
    }
    return false;
}

RipPacket constructResponseRip() {
    RipPacket ret;
    ret.numEntries = routingTable.size();
    ret.command = 2;
    for (int i = 0; i < ret.numEntries; i++) {
        ret.entries[i].addr = routingTable[i].addr;
        ret.entries[i].mask = htonl(0xffffffff << (32 - routingTable[i].len));
        ret.entries[i].nexthop = routingTable[i].nexthop;
        ret.entries[i].metric = routingTable[i].metric;
    }
    return ret;
}

RipPacket constructResponseRip(const uint32_t &ignore) {
    RipPacket ret;
    ret.numEntries = 0;
    ret.command = 2;
    for (int i = 0; i < routingTable.size(); i++) {
        uint32_t mask = htonl(0xffffffff << (32 - routingTable[i].len));
        if ((ignore & mask) == (routingTable[i].addr & mask))
            continue;
        ret.entries[ret.numEntries].addr = routingTable[i].addr;
        ret.entries[ret.numEntries].mask = mask;
        ret.entries[ret.numEntries].nexthop = routingTable[i].nexthop;
        ret.entries[ret.numEntries].metric = routingTable[i].metric;
        ret.numEntries++;
    }
    return ret;
}
