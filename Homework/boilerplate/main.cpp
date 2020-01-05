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
extern void response(RipPacket *resp, uint32_t if_index, int table_index);
extern void printTable();
extern int getRoutingTableSize();

uint32_t addWhile(uint32_t a, uint32_t b);
int format_packet(in_addr_t src_addr, in_addr_t dst_addr, RipPacket *resp, uint8_t* buffer);
void setSrcAddr(in_addr_t src_addr, uint8_t *buffer);

uint8_t packet[2048];
uint8_t output[2048];
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0100000a, 0x0101000a};
in_addr_t multicast_addr = {0x090000e0};

int main(int argc, char *argv[]) {
  int res = HAL_Init(1, addrs);
  if (res < 0) return res;
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0x00ffffff,
        .len = 24,
        .if_index = i,
        .nexthop = 0,
        .metric = 1
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
      printf("\n5s Timer\n");
      printf("Routing Table Size Is %u", getRoutingTableSize());
      for(int i=0; i<N_IFACE_ON_BOARD; i++){
        for(int j=0; j<getRoutingTableSize(); j+=25){
          RipPacket resp;
          macaddr_t dest_mac;
          response(&resp, i, j);
          int rip_len = format_packet(addrs[i], multicast_addr, &resp, output);
          HAL_ArpGetMacAddress(i, multicast_addr, dest_mac);
          HAL_SendIPPacket(i, output, rip_len + 20 + 8, dest_mac);
        }
      }
      printTable();
      last_time = time;
      printf("\n");
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac, 1000, &if_index);

    if (res == HAL_ERR_EOF) { break; }
    else if (res < 0) { return res; }
    else if (res == 0) { continue; }
    else if (res > sizeof(packet)) { continue; }

    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }

    in_addr_t src_addr, dst_addr;
    src_addr = 0x00000000;
    dst_addr = 0x00000000;
    for(int offset = 12;offset < 16;offset ++){
      src_addr += (packet[offset] << ((offset - 12) * 8));
      dst_addr += (packet[offset+4] << ((offset - 12)* 8));
    }

    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) { dst_is_me = true; break; }
    }
    dst_is_me = dst_is_me || memcmp(&dst_addr, &multicast_addr, sizeof(in_addr_t)) == 0 ;

    if (dst_is_me) {
      if(((packet[20] << 8) + packet[21] != 520) || ((packet[22] << 8) + packet[23] != 520)) continue;
      RipPacket rip;
      if (disassemble(packet, res, &rip)) {
        bool wrong_metric = false;
        if (rip.command != 1) {
          printf("\n*** Get Response Packet From %08x ***\n", src_addr);
          int invalidNum = 0;
          for(int i=0;i<rip.numEntries;i++){
            uint32_t correct_mask = ntohl(rip.entries[i].mask);
            uint32_t len = 0;
            while(correct_mask << len !=  0) { len ++; }
            RoutingTableEntry routingTableEntry = {
              .addr = rip.entries[i].addr,
              .len = len,
              .if_index = (uint32_t)if_index,
              .nexthop = src_addr,
              .metric = rip.entries[i].metric+1
            };
            if(rip.entries[i].metric + 1 < 16) update(routingTableEntry);
          }
        }
      }
    } else { // !dst_is_me
      printf("\n*** Get Forward Packet From %08x To %08x ***\n", src_addr, dst_addr);
      uint32_t nexthop, dest_if;

      if (query(dst_addr, &nexthop, &dest_if)) {
        printf("Found\n");
        macaddr_t dest_mac;
        if (nexthop == 0) nexthop = dst_addr;
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          memcpy(output, packet, res);
          forward(output, res);
          if(output[8] == 0) continue;
          HAL_SendIPPacket(dest_if, output, res, dest_mac);
        } else printf("ARP not found for %x\n", nexthop);
      } else printf("IP not found for %x\n", src_addr);
    }
  }
  return 0;
}

uint32_t addWhile(uint32_t a, uint32_t b){
  int res = a+b;
  while(res  >= 65536) res = (res & 0xFFFF) + (res >> 16);
  return res;
}

int format_packet(in_addr_t src_addr, in_addr_t dst_addr, RipPacket *resp, uint8_t* buffer){
  buffer[0] = 0x45;
  buffer[1] = 0xc0;
  for(int offset = 4;offset < 8; offset++) buffer[offset] = 0x00;
  buffer[8] = 0x01;
  buffer[9] = 0x11;
  buffer[10] = 0x00;
  buffer[11] = 0x00;
  for(int offset = 12;offset < 16;offset ++) buffer[offset] = (src_addr >> ((offset - 12) * 8) )& 0xff;
  for(int offset = 16;offset < 20;offset ++) buffer[offset] = dst_addr >> (((offset - 16) * 8)) & 0xff;
  buffer[20] = 0x02;
  buffer[21] = 0x08;
  buffer[22] = 0x02;
  buffer[23] = 0x08;
  buffer[26] = 0x00;
  buffer[27] = 0x00;
  uint32_t rip_len = assemble(resp, &buffer[20 + 8]);
  uint32_t ip_total_len = rip_len + 28;
  buffer[2] = (ip_total_len & 0xff00) >> 8;
  buffer[3] = ip_total_len & 0xff;
  uint32_t udp_len = rip_len + 8;
  buffer[24] = (udp_len & 0xff00) >> 8;
  buffer[25] = udp_len & 0xff;
  uint32_t checksum = 0x0000;
  for(int offset = 0 ; offset< 20 ; offset+=2) checksum = addWhile(checksum, (unsigned)(buffer[offset] << 8)+buffer[offset+1]);
  checksum = (~checksum) & 0xffff;
  buffer[10] = (checksum & 0xff00) >> 8;
  buffer[11] = checksum & 0xff;
  return rip_len;
}

void setSrcAddr(in_addr_t src_addr, uint8_t *buffer){
  for(int offset = 12;offset < 16;offset ++) buffer[offset] = (src_addr >> ((offset - 12) * 8) )& 0xff;
}
