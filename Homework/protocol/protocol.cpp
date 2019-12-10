#include "rip.h"
#include <stdint.h>
#include <stdlib.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'packet[lengthOfHead+13+i*20]', as it is always 2(for response) and 0(for request)
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
  if(((uint32_t)((packet[2]<<8)+packet[3]) > len)||(packet[29]!=0x2 && (packet[31]||1111||packet[30]))) return false;
  //长度问题 传入的 IP 包视为不合法  Command version zero tag


  output->numEntries = (((uint32_t)((packet[2]<<8)+packet[3]))-((packet[0]&0x0f)<<2)-12)/20;
  output->command = packet[((packet[0]&0x0f)<<2)+8];
  uint32_t lengthOfHead = ((packet[0]&0x0f)<<2);

  for(uint32_t i=0; i<(((uint32_t)((packet[2]<<8)+packet[3]))-lengthOfHead-12)/20; i++){
    uint8_t tag = packet[lengthOfHead+14+i*20]||packet[lengthOfHead+15+i*20];
    int check = 0;
    for(int m=3;m>=0;m--){
      uint8_t mask = packet[lengthOfHead+20+m+i*20];
      int count = 1;
      while(mask!=0){
        if(check==2) return false;
        if((mask&1)==1&&!check) check=1;
        if(check&&(mask&1)==0) check=2;
        if((mask&1)==1&&(mask>>1)==0&&(count<8)) check=2;
        count += 1;
        mask = mask>>1;
      }
    }

    uint32_t metric = ((int)packet[lengthOfHead+28+i*20]<<24)+((int)packet[lengthOfHead+29+i*20]<<16)+((int)packet[lengthOfHead+30+i*20]<<8)+packet[lengthOfHead+31+i*20];
    if((metric<=16&&metric>0&&(packet[lengthOfHead+13+i*20]==packet[lengthOfHead+8])&&!tag)||(packet[lengthOfHead+8]==0x1&&packet[lengthOfHead+13+i*20]==0x0)){
      output->entries[i].addr = ((int)packet[lengthOfHead+19+i*20]<<24)+((int)packet[lengthOfHead+18+i*20]<<16)+((int)packet[lengthOfHead+17+i*20]<<8)+packet[lengthOfHead+16+i*20];
      output->entries[i].mask = ((int)packet[lengthOfHead+23+i*20]<<24)+((int)packet[lengthOfHead+22+i*20]<<16)+((int)packet[lengthOfHead+21+i*20]<<8)+packet[lengthOfHead+20+i*20];
      output->entries[i].metric = ((int)packet[lengthOfHead+31+i*20]<<24)+((int)packet[lengthOfHead+30+i*20]<<16)+((int)packet[lengthOfHead+29+i*20]<<8)+packet[lengthOfHead+28+i*20];
      output->entries[i].nexthop = ((int)packet[lengthOfHead+27+i*20]<<24)+((int)packet[lengthOfHead+26+i*20]<<16)+((int)packet[lengthOfHead+25+i*20]<<8)+packet[lengthOfHead+24+i*20];
    } else { return false; }
  }
  return true;
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
  buffer[0]=rip->command;
  buffer[1]=0x02;
  buffer[2]=0x00;
  buffer[3]=0x00;

  for(uint32_t i=0; i<rip->numEntries; i++){
    if(rip->command==0x2){
      buffer[4+i*20]=0x00;
      buffer[5+i*20]=0x02;
    } else {
      buffer[4+i*20]=0x00;
      buffer[5+i*20]=0x00;
    }
    buffer[6+i*20]=0x00;
    buffer[7+i*20]=0x00;

    buffer[8+i*20]=(rip->entries[i]).addr;
    buffer[9+i*20]=(rip->entries[i]).addr>>8;
    buffer[10+i*20]=(rip->entries[i]).addr>>16;
    buffer[11+i*20]=(rip->entries[i]).addr>>24;
    buffer[12+i*20]=(rip->entries[i]).mask;
    buffer[13+i*20]=(rip->entries[i]).mask>>8;
    buffer[14+i*20]=(rip->entries[i]).mask>>16;
    buffer[15+i*20]=(rip->entries[i]).mask>>24;
    buffer[16+i*20]=(rip->entries[i]).nexthop;
    buffer[17+i*20]=(rip->entries[i]).nexthop>>8;
    buffer[18+i*20]=(rip->entries[i]).nexthop>>16;
    buffer[19+i*20]=(rip->entries[i]).nexthop>>24;
    buffer[20+i*20]=(rip->entries[i]).metric;
    buffer[21+i*20]=(rip->entries[i]).metric>>8;
    buffer[22+i*20]=(rip->entries[i]).metric>>16;
    buffer[23+i*20]=(rip->entries[i]).metric>>24;
  }
  return (rip->numEntries)*20+4;
}
