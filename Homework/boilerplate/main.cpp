#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <vector>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UDPPROTOCOL 0x11
#define ICMPPROTOCOL 0x1


extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric, uint32_t *timestamp);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern void fillResp(RipPacket* resp, int command);
extern int getChecksum(uint8_t *packet, size_t len);

uint32_t getLen(uint32_t mask) {
  uint32_t len=0;
  while(mask != 0) {
    mask = mask << 1;
    len += 1;
  }
  return len;
}

void fillIPHeader(uint8_t *packet, uint32_t totallen, uint32_t src_addr, uint32_t dest_addr, uint8_t protocol)
{
  //uint32_t numEntry = (totallen - HeaderLen - 12) / 20;

  packet[0] = 0x45;
  packet[1] = 0x00; //ECN
  packet[2] = totallen >> 8;
  packet[3] = totallen & 0xff;
  packet[4] = 0x00; //ID
  packet[5] = 0x00; //ID
  packet[6] = 0x00; //fragment
  packet[7] = 0x00; //fragment
  packet[8] = 0x01; //TTL
  packet[9] = protocol;
  //src
  packet[12] = src_addr >>24;
  packet[13] = src_addr >> 16 & 0x0f;
  packet[14] = src_addr >> 8 & 0x0f;
  packet[15] = src_addr & 0x0f;
  //dst
  packet[16] = dest_addr >> 24;
  packet[17] = dest_addr >> 16 & 0x0f;
  packet[18] = dest_addr >> 8 & 0x0f;
  packet[19] = dest_addr &0x0f;
}


RoutingTableEntry convertToRTE(RipEntry ripEntry, uint32_t if_index, in_addr_t src_addr)
{
  RoutingTableEntry routingTableEntry;
  routingTableEntry.addr = ripEntry.addr;
  routingTableEntry.len = getLen(ripEntry.mask);
  routingTableEntry.if_index = if_index;
  routingTableEntry.nexthop = src_addr;
  routingTableEntry.metric = ripEntry.metric + 1;
  if (routingTableEntry.metric > 16) routingTableEntry.metric = 16;
  routingTableEntry.timestamp = 0;
  return routingTableEntry;
}

uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t multicast_addr = 0x090000e0;
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a, 0x0103000a};

int main(int argc, char *argv[]) {
  macaddr_t multicast_mac = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x09};
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
        .addr = addrs[i] & 0x00FFFFFF, // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,     // big endian, means direct
        .metric = 0,
        .timestamp = 0
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 30 * 1000) {
      // What to do?
      // send complete routing table to every interface
      // ref. RFC2453 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
      RipPacket resp;
      fillResp(&resp, 2);
      output[20] = 0x02;
      output[21] = 0x08;
      //dest port
      output[22] = 0x02;
      output[23] = 0x08;
      output[24] = 0x0;
      output[25] = 0x0;
      output[26] = 0x0;
      output[27] = 0x0;

      uint32_t rip_len = assemble(&resp, &output[20 + 8]);
      for(int i = 0; i < 4; i++) {
        fillIPHeader(output, rip_len + 28, addrs[i], multicast_addr, UDPPROTOCOL);
        int checksum = getChecksum(output, res);
        output[10] = checksum >> 8;
        output[11] = checksum & 0xff;
        HAL_SendIPPacket(i, output, rip_len + 20 + 8, multicast_mac);
      }

      printf("30s Timer\n");
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac, 1000, &if_index);

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
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian
    src_addr = (packet[12] << 24) + (packet[13] << 16) + (packet[14] << 8) + packet[15];
    dst_addr = (packet[16] << 24) + (packet[17] << 16) + (packet[18] << 8) + packet[19];

    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // TODO: Handle rip multicast address(224.0.0.9)?

    if (dst_is_me) {
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab
          RipPacket resp;
          // TODO: fill resp
          fillResp(&resp, 2);
          // assemble
          // UDP
          // port = 520
          output[20] = 0x02;
          output[21] = 0x08;
          //dest port
          output[22] = 0x02;
          output[23] = 0x08;
          output[24] = 0x0;
          output[25] = 0x0;
          output[26] = 0x0;
          output[27] = 0x0;
          // ...
          // RIP
          uint32_t rip_len = assemble(&resp, &output[20 + 8]);
          fillIPHeader(output, rip_len + 28, dst_addr, src_addr, UDPPROTOCOL);
          // checksum calculation for ip and udp
          int checksum = getChecksum(output, res);
          output[10] = checksum >> 8;
          output[11] = checksum & 0xff;
          // if you don't want to calculate udp checksum, set it to zero
          // send it back
          HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
        } else {
          // 3a.2 response, ref. RFC2453 3.9.2
          // update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // what is missing from RoutingTableEntry?
          // TODO: use query and update
          // triggered updates? ref. RFC2453 3.10.1

          //构建触发更新的包
          RipPacket ripPacketForSend;
          std::vector<RipEntry> ripEntriesForSend;

          for(int i=0; i<rip.numEntries; i++) {
            if (rip.entries[i].metric + 1 >= 16) { // 不可达 Entry 毒化
              update(false, convertToRTE(rip.entries[i], if_index, src_addr));
              rip.entries[i].metric = 16;
              rip.entries[i].nexthop = 0;
              ripEntriesForSend.push_back(rip.entries[i]);
            } else { //可达
              uint32_t cur_nexthop, cur_if_index, cur_metric, cur_timestamp;
              bool isFound = query(rip.entries[i].addr, &cur_nexthop, &cur_if_index, &cur_metric, &cur_timestamp);
              if ((isFound && rip.entries[i].metric+1 < cur_metric) || !isFound) {
                update(true, convertToRTE(rip.entries[i], if_index, src_addr));
                rip.entries[i].metric += 1;
                rip.entries[i].nexthop = 0;
                ripEntriesForSend.push_back(rip.entries[i]);
              }
            }
          } //检查完包内所有entry

          ripPacketForSend.numEntries = ripEntriesForSend.size();
          if (ripPacketForSend.numEntries != 0) {
            ripPacketForSend.command = 2;
            for (int i=0; i<ripEntriesForSend.size(); i++) ripPacketForSend.entries[i] = ripEntriesForSend.at(i);
            output[20] = 0x02;
            output[21] = 0x08;
            output[22] = 0x02;
            output[23] = 0x08;
            output[24] = 0x0;
            output[25] = 0x0;
            output[26] = 0x0;
            output[27] = 0x0;
            uint32_t ripPacketForSendLen = assemble(&ripPacketForSend, &output[20+8]);
            for(int i=0; i<4; i++) {
              if (i != if_index) {
                fillIPHeader(output, ripPacketForSendLen, addrs[i], multicast_addr, UDPPROTOCOL);
                int checksum = getChecksum(output, res);
                output[10] = checksum >> 8;
                output[11] = checksum & 0xff;
                HAL_SendIPPacket(i, output, ripPacketForSendLen+20+8, multicast_mac);
              }
            }
          }
        }
      }
    } else {
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if, metric, timestamp;
      if (query(dst_addr, &nexthop, &dest_if, &metric, &timestamp)) {
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
          if (output[8] == 0) {
            uint32_t total_len = 20 + 8 + 20 + 8;
            fillIPHeader(output, total_len, dst_addr, src_addr, ICMPPROTOCOL);
            output[20] = 0x11;
            output[21] = 0x0;
            for (int i=0; i<28; i++) {
              output[i+22] = packet[i];
            }
          }
          HAL_SendIPPacket(dest_if, output, res, dest_mac);
        } else {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      } else {
        // not found
        //return icmp destination network unreachable
        // optionally you can send ICMP Host Unreachable
        memcpy(output, packet, res);
        // update ttl and checksum
        //ttl is packet[8] for a rippacket type packet
        forward(output, res);
        // TODO: you might want to check ttl=0 case

        uint32_t total_len = 20 + 8 + 20 + 8; //my ip header, + icmp header+ original ip header+ 8
        fillIPHeader(output, total_len, dst_addr, src_addr, ICMPPROTOCOL);
        //send back to where it came from
        output[20] = 0x3;
        output[21] = 0x0;
        for(int i = 0; i < 28; i++) {
          output[i + 22] = packet[i];
        }
        HAL_SendIPPacket(dest_if, output, res, src_mac);
        printf("IP not found for %x\n", src_addr);
      }
    }
  }
  return 0;
}
