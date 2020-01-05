#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>

uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  int offset = 0;
  buffer[offset++] = (*rip).command;
  buffer[offset++] = 0x2;
  buffer[offset++] = 0;
  buffer[offset++] = 0;
  for(int i = 0 ; i < (*rip).numEntries ; i++){
    buffer[offset++] = 0;
    if((*rip).command == 2) buffer[offset++] = 2;
    else buffer[offset++] = 0;
    buffer[offset++] = 0;
    buffer[offset++] = 0;
    auto getEntry = (*rip).entries[i];
    for(int period = 0 ; period < 4 ; period++ ) buffer[offset+period] = getEntry.addr >> (period * 8);
    offset += 4;
    for(int period = 0 ; period < 4 ; period++ ) buffer[offset+period] = getEntry.mask >> (period * 8);
    offset += 4;
    for(int period = 0 ; period < 4 ; period++ ) buffer[offset+period] = getEntry.nexthop >> (period * 8);
    offset += 4;
    for(int period = 0 ; period < 4 ; period++ ) buffer[offset+period] = getEntry.metric >> ((3 - period) * 8);
    offset += 4;
  }
  return offset;
}

bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  int offset = 28;
  int command = packet[offset++];
  int version = packet[offset++];
  int zero_0 = packet[offset++];
  int zero_1 = packet[offset++];
  (*output).numEntries = 0;
  if ((command != 1 && command != 2) || (version != 2) || (zero_0 != 0 || zero_1 != 0)) return false;
  else {
    for(int i=0 ; offset < len - 1 ; i++){
      int family = (packet[offset++] << 8) + packet[offset++];
      int tag = (packet[offset++] << 8) + packet[offset++];
      if((command == 2 && family != 2) || (command == 1 && family != 0) || (tag != 0)) return false;
      RipEntry& getEntry = ((*output).entries[i]);
      getEntry.addr = (packet[offset]) + (packet[offset+1] << 8) + (packet[offset+2] << 16) + (packet[offset+3] << 24);
      offset += 4;
      getEntry.mask =  (packet[offset]) + (packet[offset+1] << 8) + (packet[offset+2] << 16) + (packet[offset+3] << 24);
      offset += 4;
      int checkingMask = getEntry.mask + 1;
      bool correctness = false;
      for(int j = 0;j<31;j++){
        if((1 << j) == checkingMask){
          correctness = true;
          break;
        }
      }
      if(!correctness) return false;
      getEntry.nexthop =  (packet[offset]) + (packet[offset+1] << 8) + (packet[offset+2] << 16) + (packet[offset+3] << 24);
      offset += 4;
      getEntry.metric =  (packet[offset] << 24) + (packet[offset+1] << 16) + (packet[offset+2] << 8) + (packet[offset+3]);
      offset += 4;
      if(getEntry.metric < 1 || getEntry.metric > 16) return false;
      (*output).numEntries ++;
    }
    (*output).command = command;
    if(offset > len) return false;
    else return true;
  }
}
