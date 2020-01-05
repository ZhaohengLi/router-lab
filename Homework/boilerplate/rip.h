#include <stdint.h>
#define RIP_MAX_ENTRY 25

typedef struct {
  uint32_t addr;
  uint32_t mask;
  uint32_t nexthop;
  uint32_t metric;
} RipEntry;

typedef struct {
  uint32_t numEntries;
  uint8_t command;
  RipEntry entries[RIP_MAX_ENTRY];
} RipPacket;
