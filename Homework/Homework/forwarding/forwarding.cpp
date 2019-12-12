#include <stdint.h>
#include <stdlib.h>

uint32_t origin_sum = 0;

bool validateIPChecksum_forward(uint8_t *packet, size_t len) {
    uint16_t checksum = (packet[10] << 8) | (packet[11]);
    size_t header_len = packet[0] & 0x0F;
    packet[10] = packet[11] = 0;
    uint32_t sum = 0;
    for (size_t i = 0; i < header_len * 4; i += 2) {
        sum += (packet[i] << 8) | (packet[i+1]);
    }
    origin_sum = sum;
    while (sum >> 16 > 0) {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    packet[10] = checksum >> 8;
    packet[11] = checksum & 0xff;

    uint16_t ans = ~sum & 0xffff;
    
    return ans == checksum;
}

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
    if (validateIPChecksum_forward(packet, len)) {
        packet[8] -= 1;
        origin_sum -= 1 << 8;
        while (origin_sum >> 16 > 0) {
            origin_sum = (origin_sum >> 16) + (origin_sum & 0xffff);
        }
        uint16_t ans = ~origin_sum & 0xffff;
        packet[10] = ans >> 8;
        packet[11] = ans & 0xff;
        return true;
    }
    else {
        return false;
    }
}
