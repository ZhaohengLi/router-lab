#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(response) and 0(request)
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
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
    uint16_t tot_len = (packet[2] << 8) | (packet[3] & 0xff);
    if (tot_len > len) {
        return false;
    }

    uint8_t ip_header_len = (packet[0] & 0x0F) * 4;
    uint8_t udp_header_len = 8;
    uint8_t header_len = ip_header_len + udp_header_len;
    uint8_t num = (tot_len - header_len) / 20;

    uint8_t command = packet[header_len];
    uint8_t version = packet[header_len + 1];
    uint16_t zero = (packet[header_len + 2] << 8) | packet[header_len + 3];

    if (command != 1 && command != 2) {
        return false;
    }
    if (version != 2) {
        return false;
    }
    if (zero != 0) {
        return false;
    }

    output->numEntries = 0;

    for (uint8_t i = header_len + 4; i < tot_len; i += 20) {
        uint16_t family = (packet[i] << 8) | packet[i+1];
        uint16_t tag = (packet[i+2] << 8) | packet[i+3];
        uint32_t ip = *(uint32_t*)(packet + i + 4);
        uint32_t netmask = *(uint32_t*)(packet + i + 8);
        uint32_t nexthop = *(uint32_t*)(packet + i + 12);
        uint32_t metric = ntohl(*(uint32_t*)(packet + i + 16));
        if (command == 1 && family != 0) {
            return false;
        }
        if (command == 2 && family != 2) {
            return false;
        }
        if (tag != 0) {
            return false;
        }
        if (metric < 1 || metric > 16) {
            return false;
        }
        uint32_t tmp = ntohl(netmask);
        for (int i = 0; i < 32; i++) {
            if (tmp == 0) {
                break;
            }
            if ( ((tmp >> 31) & 1) == 1 ) {
                tmp <<= 1;
            }
            else {
                return false;
            }
        }

        auto &entry = output->entries[output->numEntries++];
        entry.addr = ip;
        entry.mask = netmask;
        entry.nexthop = nexthop;
        entry.metric = metric;
    }

    output->command = command;
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
    buffer[0] = rip->command;
    buffer[1] = 2;
    buffer[2] = buffer[3] = 0;
    uint32_t top = 4;
    for (int i = 0; i < rip->numEntries; i++) {
        buffer[top] = 0;
        buffer[top+1] = rip->command == 1 ? 0 : 2;
        buffer[top+2] = buffer[top+3] = 0;
        *(uint32_t*)(buffer+top+4) = rip->entries[i].addr;
        *(uint32_t*)(buffer+top+8) = rip->entries[i].mask;
        *(uint32_t*)(buffer+top+12) = rip->entries[i].nexthop;
        *(uint32_t*)(buffer+top+16) = htonl(rip->entries[i].metric);
        top += 20;      
    }
    return 4 + rip->numEntries * 20;
}
