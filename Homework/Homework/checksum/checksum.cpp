#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
    uint16_t checksum = (packet[10] << 8) | (packet[11]);
    size_t header_len = packet[0] & 0x0F;
    packet[10] = packet[11] = 0;
    uint32_t sum = 0;
    for (size_t i = 0; i < header_len * 4; i += 2) {
        sum += (packet[i] << 8) | (packet[i+1]);
    }
    while (sum >> 16 > 0) {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    packet[10] = checksum >> 8;
    packet[11] = checksum & 0xff;

    uint16_t ans = ~sum & 0xffff;
    
    return ans == checksum;
}
