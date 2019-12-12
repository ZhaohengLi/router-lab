#include <stdint.h>
#include <stdlib.h>
#include<stdio.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */


   unsigned int addWhileC(unsigned int a, unsigned int b){
     int res = a+b;
     while(res  >= 65536)
       res = (res & 0xFFFF) + (res >> 16);
     return res;
   }

bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
  int head_length = (packet[0] % 16)  * 4;
  unsigned int sum = (packet[10] << 8) + packet[11];
  unsigned int predict_sum = 0;
  auto phi = packet[10];
  auto plo = packet[11];
  packet[10] = 0;
  packet[11] = 0;
  for(int i = 0 ; i < head_length/2 ; i++){
    predict_sum = addWhileC(predict_sum, (unsigned)(packet[i*2] << 8)+packet[2*i+1]);
    }
  predict_sum = (~predict_sum) & 0xFFFF;
  packet[10] = phi;
  packet[11] = plo;
  return predict_sum == sum;
}
