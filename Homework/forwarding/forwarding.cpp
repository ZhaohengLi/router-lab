#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  uint8_t IHL = packet[0] & 0x0F;
  int sum = 0;

  for(int i=0; i<(IHL*4); i+=2){
      sum += (packet[i]<<8);
      sum += packet[i+1];
  }
  while(sum > 0xFFFF){ sum = (sum>>16) + (sum&0xFFFF); }
  if(sum != 0xFFFF) return false;

  packet[8] -= 1;
  sum = 0;
  for(int i=0; i<(IHL*4); i+=2){
      if(i==10) continue;
      sum += (packet[i]<<8);
      sum += packet[i+1];
  }
  while(sum > 0xFFFF){ sum = (sum>>16) + (sum&0xFFFF); }
  sum = (~sum)&0xFFFF;
  packet[10] = (sum&0xFF00)>>8;
  packet[11] = sum&0x00FF;

  return true;
}
