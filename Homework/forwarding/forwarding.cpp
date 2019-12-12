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

   unsigned int addWhileF(unsigned int a, unsigned int b){
     int res = a+b;
     while(res  >= 65536)
       res = (res & 0xFFFF) + (res >> 16);
     return res;
   }

 bool validateIPChecksumF(uint8_t *packet, size_t len) {
   // TODO:
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
  // TODO:
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
  }else{
    return false;
  }
}
