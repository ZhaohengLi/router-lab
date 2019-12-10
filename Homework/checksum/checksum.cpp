#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  uint8_t IHL = packet[0] & 0x0F;
  int sum = 0;
  for(int i=0; i<(IHL*4); i+=2){
      sum += (packet[i]<<8);
      sum += packet[i+1];
  }
  while(sum > 0xFFFF){
      sum = (sum>>16) + (sum&0xFFFF);
  }
  return sum == 0xFFFF;
}
