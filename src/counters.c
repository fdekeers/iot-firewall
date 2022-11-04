/**
 * @file src/counters.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Interface to nftables counters
 * @date 2022-11-02
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "counters.h"


/**
 * @brief Generic function to read an nftables counter value.
 *
 * @param table_name name of the nftables table containing the counter
 * @param counter_name name of the nftables counter to read
 * @param num number of the value to read (1 for packets, 2 for bytes)
 * @return value read from the counter
 */
static uint32_t counter_read_nft(char *table_name, char *counter_name, uint8_t num) {
    // Build command
    uint16_t length = 58 + strlen(table_name) + strlen(counter_name);
    char cmd[length];
    int ret = snprintf(cmd, length, "sudo nft list counter %s %s | grep packets | awk '{print $%hhu}'", table_name, counter_name, num * 2);
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
 * @param table_name name of the nftables table containing the counter
 * @param counter_name name of the nftables counter to read
 * @return packet count value of the counter
 */
uint32_t counter_read_packets(char *table_name, char *counter_name) {
    return counter_read_nft(table_name, counter_name, 1);
}

/**
 * @brief Read the bytes value of an nftables counter.
 *
 * @param table_name name of the nftables table containing the counter
 * @param counter_name name of the nftables counter to read
 * @return bytes value of the counter
 */
uint32_t counter_read_bytes(char *table_name, char *counter_name) {
    return counter_read_nft(table_name, counter_name, 2);
}

/**
 * @brief Initialize counters values.
 *
 * @param nft_table_name name of the nftables table containing the associated nftables counter
 * @param nft_counter_name name of the associated nftables counter
 * @return initial_values_t struct containing the initial values
 */
initial_values_t counters_init(char *nft_table_name, char *nft_counter_name) {
    initial_values_t initial_values;
    initial_values.is_initialized = true;
    // Initial packet count value
    initial_values.packets_out = counter_read_packets(nft_table_name, strncat(nft_counter_name, "-out", 4));
    initial_values.packets_in = counter_read_packets(nft_table_name, strncat(nft_counter_name, "-in", 3));
    initial_values.packets_both = counter_read_packets(nft_table_name, nft_counter_name);
    // Initial time value
    struct timeval tv;
    int ret = gettimeofday(&tv, NULL);
    if (ret != 0) {
        perror("counters_init - gettimeofday");
        exit(EXIT_FAILURE);
    }
    initial_values.microseconds = ((uint64_t)tv.tv_sec) * 1000000 + ((uint64_t)tv.tv_usec);
    return initial_values;
}
