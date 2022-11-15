/**
 * @file src/rule_utils.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Rule utilitaries
 * @date 2022-11-02
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "rule_utils.h"


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
    if (ret != length - 1) {
        fprintf(stderr, "Error while building command to read counter %s\n", counter_name);
        exit(EXIT_FAILURE);
    }
    // Execute command
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to run command '%s'\n", cmd);
        exit(EXIT_FAILURE);
    }
    // Read and return output
    uint32_t count;
    ret = fscanf(fp, "%u", &count);
    pclose(fp);
    if (ret != 1) {
        fprintf(stderr, "Error while reading output of command '%s'\n", cmd);
        exit(EXIT_FAILURE);
    }
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
 * @brief Read the current microseconds value.
 *
 * @return current microseconds value
 */
uint64_t counter_read_microseconds() {
    struct timeval tv;
    int ret = gettimeofday(&tv, NULL);
    if (ret != 0) {
        perror("counters_read_microseconds - gettimeofday");
        exit(EXIT_FAILURE);
    }
    return ((uint64_t) tv.tv_sec) * 1000000 + ((uint64_t) tv.tv_usec);
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
    uint16_t length = strlen(nft_counter_name) + 5;
    char counter_out[length];
    int ret = snprintf(counter_out, length, "%s-out", nft_counter_name);
    if (ret != length - 1) {
        fprintf(stderr, "Error while building counter name '%s-out'\n", nft_counter_name);
        exit(EXIT_FAILURE);
    }
    initial_values.packets_out = counter_read_packets(nft_table_name, counter_out);
    length -= 1;
    char counter_in[length];
    ret = snprintf(counter_in, length, "%s-in", nft_counter_name);
    if (ret != length - 1) {
        fprintf(stderr, "Error while building counter name '%s-in'\n", nft_counter_name);
        exit(EXIT_FAILURE);
    }
    initial_values.packets_in = counter_read_packets(nft_table_name, counter_in);
    initial_values.packets_both = counter_read_packets(nft_table_name, nft_counter_name);
    // Initial time value
    initial_values.microseconds = counter_read_microseconds();
    return initial_values;
}

/**
 * @brief Delete an nftables rule.
 *
 * Retrieves the rule handle,
 * then deletes the rule.
 *
 * @param nft_table nftables table containing the rule
 * @param nft_chain nftables chain containing the rule
 * @param nft_rule nftables rule to delete
 * @return true if the rule was correctly deleted, false otherwise
 */
bool delete_nft_rule(char *nft_table, char *nft_chain, char *nft_rule) {
    uint16_t handle;
    // Build command to read rule handle value
    uint16_t length = 65 + strlen(nft_table) + strlen(nft_chain) + strlen(nft_rule);
    char read_handle_cmd[length];
    int ret = snprintf(read_handle_cmd, length, "sudo nft -a list chain %s %s | grep '%s' | grep -o -E 'handle [0-9]+$'", nft_table, nft_chain, nft_rule);
    if (ret != length - 1) {
        fprintf(stderr, "Error while building command to read rule handle value\n");
        return false;
    }
    // Execute command to read rule handle value
    FILE *fp = popen(read_handle_cmd, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to run command '%s'\n", read_handle_cmd);
        return false;
    }
    // Read rule handle value
    ret = fscanf(fp, "handle %hu", &handle);
    pclose(fp);
    if (ret != 1) {
        fprintf(stderr, "Error while reading output of command '%s'\n", read_handle_cmd);
        return false;
    }
    // Build command to delete the correspondig nftables rule
    length = 34 + strlen(nft_table) + strlen(nft_chain);
    char delete_handle_cmd[length];
    ret = snprintf(delete_handle_cmd, length, "sudo nft delete rule %s %s handle %hu", nft_table, nft_chain, handle);
    if (ret < length -3 || ret > length - 1) {
        fprintf(stderr, "Error while building command to delete rule with handle %hu\n", handle);
        return false;
    }
    // Execute command to delete the corresponding nftables rule
    ret = system(delete_handle_cmd);
    if (ret == -1) {
        fprintf(stderr, "Failed to run command '%s'\n", delete_handle_cmd);
        return false;
    } else {
        printf("Successfully deleted rule with handle %hu\n", handle);
        return true;
    }
}
