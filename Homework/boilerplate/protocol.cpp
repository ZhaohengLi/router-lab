#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include<stdio.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // TODO:
  int offset = 28;
  int command = packet[offset++];
  int version = packet[offset++];
  int zero_0 = packet[offset++];
  int zero_1 = packet[offset++];
  (*output).numEntries = 0;
  if((command != 1 && command != 2) || (version != 2) || (zero_0 != 0 || zero_1 != 0))
    return false;
  else{
    for(int i=0 ; offset < len - 1 ; i++){
      int family = (packet[offset++] << 8) + packet[offset++];
      int tag = (packet[offset++] << 8) + packet[offset++];
      if((command == 2 && family != 2) || (command == 1 && family != 0) || (tag != 0))
        return false;
      // printf("command: %d, version: %d, zero: %d, family: %d, tag: %d\n", command, version, (zero_0 << 8) + zero_1, family, tag);
      RipEntry& getEntry = ((*output).entries[i]);
      getEntry.addr = (packet[offset]) + (packet[offset+1] << 8) + (packet[offset+2] << 16) + (packet[offset+3] << 24);
      offset += 4;
      getEntry.mask =  (packet[offset]) + (packet[offset+1] << 8) + (packet[offset+2] << 16) + (packet[offset+3] << 24);
      // printf("addr: 0x%08x, mask: 0x%08x\n", getEntry.addr, getEntry.mask);
      offset += 4;
      int checkingMask = getEntry.mask + 1;
      bool correctness = false;
      for(int j = 0;j<31;j++){
        // printf("checking: %d\n", checkingMask >> j);
        if((1 << j) == checkingMask){
          correctness = true;
          break;
        }
      }
      if(!correctness)
        return false;
      getEntry.nexthop =  (packet[offset]) + (packet[offset+1] << 8) + (packet[offset+2] << 16) + (packet[offset+3] << 24);
      offset += 4;
      getEntry.metric =  (packet[offset] << 24) + (packet[offset+1] << 16) + (packet[offset+2] << 8) + (packet[offset+3]);
      offset += 4;
      // printf("%u", getEntry.metric);
      // int realMetric = ntohl(getEntry.metric);
      if(getEntry.metric < 1 || getEntry.metric > 16)
        return false;
      // getEntry.metric = realMetric;
      (*output).numEntries ++;
    }
    (*output).command = command;
    if(offset > len)
      return false;
    else
      return true;
  }
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  int offset  = 0;
  buffer[offset++] = (*rip).command;
  buffer[offset++] = 0x2;
  buffer[offset++] = 0;
  buffer[offset++] = 0;
  for(int i = 0 ; i < (*rip).numEntries ; i++){
    buffer[offset++] = 0;
    if((*rip).command == 2)
      buffer[offset++] = 2;
    else 
      buffer[offset++] = 0;
    buffer[offset++] = 0;
    buffer[offset++] = 0;
    auto getEntry = (*rip).entries[i];
    for(int period = 0 ; period < 4 ; period++ )
      buffer[offset+period] = getEntry.addr >> (period * 8);
    offset += 4;
    for(int period = 0 ; period < 4 ; period++ )
      buffer[offset+period] = getEntry.mask >> (period * 8);
    offset += 4;
    for(int period = 0 ; period < 4 ; period++ )
      buffer[offset+period] = getEntry.nexthop >> (period * 8);
    offset += 4;
    // printf("%u\n", getEntry.metric);
    for(int period = 0 ; period < 4 ; period++ )
      buffer[offset+period] = getEntry.metric >> ((3 - period) * 8);
    offset += 4;
  }
  return offset;
}
