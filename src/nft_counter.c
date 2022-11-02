/**
 * @file nft_counter.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Interface to nftables counters
 * @date 2022-11-02
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "nft_counter.h"

/**
 * @brief Generic function to read an nftables counter value.
 *
 * @param counter_name name of the nftables counter to read
 * @param num number of the value to read (1 for packets, 2 for bytes)
 * @return value read from the counter
 */
static uint32_t counter_read(char *counter_name, uint8_t num) {
    // Build command
    uint16_t length = 52 + strlen(counter_name);
    char cmd[length];
    int ret = snprintf(cmd, length, "nft list counter %s | grep packets | awk '{print $%hhu}'", counter_name, num * 2);
    if (ret != length - 1)
    {
        fprintf(stderr, "Error while building command to read counter %s\n", counter_name);
        exit(EXIT_FAILURE);
    }
    // Execute command
    FILE *fp = popen(cmd, "r");
    if (fp == NULL)
    {
        fprintf(stderr, "Failed to run command '%s'\n", cmd);
        exit(EXIT_FAILURE);
    }
    // Read and return output
    uint32_t count;
    ret = fscanf(fp, "%u", &count);
    if (ret != 1)
    {
        fprintf(stderr, "Error while reading output of command '%s'\n", cmd);
        exit(EXIT_FAILURE);
    }
    pclose(fp);
    return count;
}

/**
 * @brief Read the packet count value of an nftables counter.
 *
 * @param counter_name name of the nftables counter to read
 * @return packet count value of the counter
 */
uint32_t counter_read_packets(char *counter_name) {
    return counter_read(counter_name, 1);
}

/**
 * @brief Read the bytes value of an nftables counter.
 *
 * @param counter_name name of the nftables counter to read
 * @return bytes value of the counter
 */
uint32_t counter_read_bytes(char *counter_name) {
    return counter_read(counter_name, 2);
}
