#include <stdint.h>
#include <stdlib.h>
#include<stdio.h>

unsigned int addWhileC(unsigned int a, unsigned int b){
  int res = a+b;
  while(res  >= 65536)
    res = (res & 0xFFFF) + (res >> 16);
  return res;
}

bool validateIPChecksum(uint8_t *packet, size_t len) {
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
