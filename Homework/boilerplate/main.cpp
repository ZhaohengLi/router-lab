#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern void update(RoutingTableEntry entry);
extern void response(RipPacket *resp, uint32_t if_index);
extern void printTable();

uint32_t addWhile(uint32_t a, uint32_t b){
  int res = a+b;
  while(res  >= 65536)
    res = (res & 0xFFFF) + (res >> 16);
  return res;
}

int format_packet(in_addr_t src_addr, in_addr_t dst_addr, RipPacket *resp, uint8_t* buffer){
  buffer[0] = 0x45;
  buffer[1] = 0xc0;

  // IP Id, flags, TTL and protocol
  for(int offset = 4;offset < 8; offset++)
    buffer[offset] = 0x00;

  buffer[8] = 0x01;
  buffer[9] = 0x11;
  // IP Header Checksum(placeholder)
  buffer[10] = 0x00;
  buffer[11] = 0x00;
  // IP Source Addr
  for(int offset = 12;offset < 16;offset ++)
    buffer[offset] = (src_addr >> ((offset - 12) * 8) )& 0xff;
  // IP Dest Addr = 224.0.0.9
  for(int offset = 16;offset < 20;offset ++)
    buffer[offset] = dst_addr >> (((offset - 16) * 8)) & 0xff;
  // UDP
  // port = 520
  buffer[20] = 0x02;
  buffer[21] = 0x08;
  buffer[22] = 0x02;
  buffer[23] = 0x08;

  // Checksum = ?(placeholder)
  buffer[26] = 0x00;
  buffer[27] = 0x00;

  // RIP
  uint32_t rip_len = assemble(resp, &buffer[20 + 8]);
  // length calculation for ip and udp
  // ip total length calculate
  uint32_t ip_total_len = rip_len + 28;
  buffer[2] = (ip_total_len & 0xff00) >> 8;
  buffer[3] = ip_total_len & 0xff;
  // udp length calculate
  uint32_t udp_len = rip_len + 8;
  buffer[24] = (udp_len & 0xff00) >> 8;
  buffer[25] = udp_len & 0xff;
  // checksum calculation for ip and udp
  // ip header checksum calculation
  uint32_t checksum = 0x0000;
  for(int offset = 0 ; offset< 20 ; offset+=2){
    checksum = addWhile(checksum, (unsigned)(buffer[offset] << 8)+buffer[offset+1]);
    }
  checksum = (~checksum) & 0xffff;
  buffer[10] = (checksum & 0xff00) >> 8;
  buffer[11] = checksum & 0xff;
  // if you don't want to calculate udp checksum, set it to zero
  // udp checksum calculating, maybe not using it now
  return rip_len;
}

void setSrcAddr(in_addr_t src_addr, uint8_t *buffer){
  for(int offset = 12;offset < 16;offset ++)
    buffer[offset] = (src_addr >> ((offset - 12) * 8) )& 0xff;
}

uint8_t packet[2048];
uint8_t output[2048];
// 0: 192.168.3.2
// 1: 192.168.4.1
// 2: 10.0.0.1
// 3: 10.0.1.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0100000a, 0x0101000a};

// Multicast addr
// 224.0.0.9
in_addr_t multicast_addr = {0x090000e0};

int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // 0b. Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0x00ffffff, // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,     // big endian, means direct
        .metric = 1
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
      // What to do?
      // send complete routing table to every interface
      for(int i=0;i < N_IFACE_ON_BOARD;i++){
        RipPacket resp;
        macaddr_t dest_mac;
        response(&resp, i);
        int rip_len = format_packet(addrs[i], multicast_addr, &resp, output);
        HAL_ArpGetMacAddress(i, multicast_addr, dest_mac);
        HAL_SendIPPacket(i, output, rip_len + 20 + 8, dest_mac);
      }
      printTable();
      // ref. RFC2453 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
      // 30秒计时器，发送全部路由表
      printf("5s Timer\n");
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac,
                                  dst_mac, 1000, &if_index);

    // 1. 检查是否是合法的 IP 包，可以用你编写的 validateIPChecksum 函数，还需要一些额外的检查
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    // 1. validate
    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }

    // 2. 检查目的地址，如果是路由器自己的 IP（或者是 RIP 的组播地址），进入 3a；否则进入 3b
    in_addr_t src_addr, dst_addr;
    src_addr = 0x00000000;
    dst_addr = 0x00000000;
    // extract src_addr and dst_addr from packet
    // big endian
    for(int offset = 12;offset < 16;offset ++){
      src_addr += (packet[offset] << ((offset - 12) * 8));
      dst_addr += (packet[offset+4] << ((offset - 12)* 8));
    }

    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }

    // TODO: Handle rip multicast address(224.0.0.9)?
    dst_is_me = dst_is_me || memcmp(&dst_addr, &multicast_addr, sizeof(in_addr_t)) == 0 ;
    // 3a.1 检查是否是合法的 RIP 包，可以用你编写的 disassemble 函数检查并从中提取出数据
    // 3a.2 如果是 Response 包，就调用你编写的 query 和 update 函数进行查询和更新，
    //      注意此时的 RoutingTableEntry 可能要添加新的字段（如metric、timestamp），
    //      如果有路由更新的情况，可能需要构造出 RipPacket 结构体，调用你编写的 assemble 函数，
    //      再把 IP 和 UDP 头补充在前面，通过 HAL_SendIPPacket 把它发到别的网口上
    // 3a.3 如果是 Request 包，就遍历本地的路由表，构造出一个 RipPacket 结构体，
    //      然后调用你编写的 assemble 函数，另外再把 IP 和 UDP 头补充在前面，
    //      通过 HAL_SendIPPacket 发回询问的网口
    // 3b.1 此时目的 IP 地址不是路由器本身，则调用你编写的 query 函数查询，
    //      如果查到目的地址，如果是直连路由， nexthop 改为目的 IP 地址，
    //      用 HAL_ArpGetMacAddress 获取 nexthop 的 MAC 地址，如果找到了，
    //      就调用你编写的 forward 函数进行 TTL 和 Checksum 的更新，
    //      通过 HAL_SendIPPacket 发到指定的网口，
    //      在 TTL 减到 0 的时候建议构造一个 ICMP Time Exceeded 返回给发送者；
    //      如果没查到目的地址的路由，建议返回一个 ICMP Destination Network Unreachable；
    //      如果没查到下一跳的 MAC 地址，HAL 会自动发出 ARP 请求，在对方回复后，下次转发时就知道了

    if (dst_is_me) {
      // The packet is meant for sending to this router
      // TODO: RIP?
      // 3a.1
      if(((packet[20] << 8) + packet[21] != 520) || ((packet[22] << 8) + packet[23] != 520))
        continue;
      RipPacket rip;
      // check and validate
      // disassemble packet into RipPacket rip variable
      if (disassemble(packet, res, &rip)) {
        // check metric of every entry in RIP request
        bool wrong_metric = false;
        if (rip.command == 1) {
          if(rip.entries[0].metric != 16)
            continue;
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab
          // request
          RipPacket resp;
          // TODO: fill resp
          response(&resp, if_index);
          // fufilling ID and UDP header, and then assemble it with resp
          int rip_len = format_packet(addrs[if_index], multicast_addr, &resp, output);
          // send it back
          HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
        } else {
          // 3a.2 response, ref. RFC2453 3.9.2
          // assemble invalid RIP packet response, maybe not using it now
          // RipPacket invalid;
          // invalid.command = 0x2;
          int invalidNum = 0;
          for(int i=0;i<rip.numEntries;i++){
            RipEntry entry = {
                .addr = rip.entries[i].addr,
                .mask = rip.entries[i].mask,
                .nexthop =rip.entries[i].nexthop == 0 ? src_addr : rip.entries[i].nexthop,
                .metric = rip.entries[i].metric
            };
            uint32_t correct_mask = ntohl(entry.mask);
            uint32_t len = 0;
            while(correct_mask << len !=  0){
              len ++;
            }
            RoutingTableEntry routingTableEntry = {
              .addr = entry.addr,
              .len = len,
              .if_index = if_index,
              .nexthop = entry.nexthop,
              .metric = entry.metric+1
            };
            if(rip.entries[i].metric + 1 >= 16){
              // invalid metric, deleting it in routing table and sending it back later
              // maybe not using it now
              // invalid.entries[invalidNum ++] = entry;
              // update(false, routingTableEntry);
            }else{
              // update routing table
              // new metric = ?
              // update metric, if_index, nexthop
              // what is missing from RoutingTableEntry?(the int "metric")
              // TODO: use query and update
              // triggered updates? ref. RFC2453 3.10.1
              update(routingTableEntry);
            }
          }
          // Send back the invalid RIP packet response throung the non-receiving ports
          // maybe not using it now
          // int rip_len = format_packet(addrs[0], multicast_addr, &invalid, output);
          // macaddr_t dest_mac;
          // for(int i=0;i<N_IFACE_ON_BOARD;i++){
          //   if(i != if_index){
          //     setSrcAddr(addrs[i], output);
          //     HAL_ArpGetMacAddress(i, multicast_addr, dest_mac);
          //     HAL_SendIPPacket(i, output, rip_len + 28, dest_mac);
          //   }
          // }
        }
      }else{
        // disassemble error, ignore this packet
      }
    } else {
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if;

      if (query(dst_addr, &nexthop, &dest_if)) {
        printf("Found\n");
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          forward(output, res);
          // TODO: you might want to check ttl=0 case
          if(output[8] == 0)
            continue;
          HAL_SendIPPacket(dest_if, output, res, dest_mac);
        } else {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      } else {
        // not found
        // optionally you can send ICMP Host Unreachable
        printf("IP not found for %x\n", src_addr);
      }
    }
  }
  return 0;
}
