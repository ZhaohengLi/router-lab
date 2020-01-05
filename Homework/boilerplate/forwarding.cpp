#include <stdint.h>
#include <stdlib.h>

unsigned int addWhileF(unsigned int a, unsigned int b){
  int res = a+b;
  while(res  >= 65536)
    res = (res & 0xFFFF) + (res >> 16);
  return res;
}

bool validateIPChecksumF(uint8_t *packet, size_t len) {
   int head_length = (packet[0] % 16)  * 4;
   unsigned int sum = (packet[10] << 8) + packet[11];
   unsigned int predict_sum = 0;
   auto phi = packet[10];
   auto plo = packet[11];
   packet[10] = 0;
   packet[11] = 0;
   for(int i = 0 ; i < head_length/2 ; i++)
     predict_sum = addWhileF(predict_sum, (unsigned)(packet[i*2] << 8)+packet[2*i+1]);
   predict_sum = (~predict_sum) & 0xFFFF;
   packet[10] = phi;
   packet[11] = plo;
   return predict_sum == sum;
 }

bool forward(uint8_t *packet, size_t len) {
  if(validateIPChecksumF(packet, len)){
    int len_head = (packet[0] % 16) * 4;
    unsigned int predict_sum = 0;
    packet[8]--;
    packet[10] = 0;
    packet[11] = 0;
    for(int i =0;i<len_head / 2;i++)
      predict_sum = addWhileF(predict_sum, (unsigned)(packet[i*2] << 8)+packet[2*i+1]);
    predict_sum =  (~predict_sum) & 0xFFFF;
    packet[10] = predict_sum >> 8;
    packet[11] = predict_sum & 0xFF;
    return true;
  } else return false;
}
