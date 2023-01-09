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
 * @param counter_type type of the counter to read
 * @return value read from the counter
 */
static uint32_t counter_read_nft(char *table_name, char *counter_name, counter_type_t counter_type) {
    // Build command
    uint16_t length = 58 + strlen(table_name) + strlen(counter_name);
    char cmd[length];
    int ret = snprintf(cmd, length, "sudo nft list counter %s %s | grep packets | awk '{print $%hhu}'", table_name, counter_name, counter_type * 2);
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
    return counter_read_nft(table_name, counter_name, PACKETS);
}

/**
 * @brief Read the bytes value of an nftables counter.
 *
 * @param table_name name of the nftables table containing the counter
 * @param counter_name name of the nftables counter to read
 * @return bytes value of the counter
 */
uint32_t counter_read_bytes(char *table_name, char *counter_name) {
    return counter_read_nft(table_name, counter_name, BYTES);
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
 * @brief Initialize the values of a packet_count_t structure.
 *
 * @param nft_table_name name of the nftables table containing the associated nftables counter
 * @param nft_counter_name name of the associated nftables counter
 * @param direction_idx index of the direction of the rule (0 for both, 1 for out, 2 for in)
 * @return packet_count_t struct containing the initial packet count values
 */
packet_count_t counter_packets_init(char *nft_table_name, char *nft_counter_name, direction_t direction)
{
    packet_count_t packet_count;
    packet_count.is_initialized = true;

    // Initial packet count value
    if (direction == BOTH) {
        packet_count.packets_both = counter_read_packets(nft_table_name, nft_counter_name);
    } else {
        // direction == IN or direction == OUT
        char* dir_str = direction == OUT ? "out" : "in";
        uint16_t dir_len = direction == OUT ? 3 : 2;
        uint16_t length = strlen(nft_counter_name) + dir_len + 2;
        char counter[length];
        int ret = snprintf(counter, length, "%s-%s", nft_counter_name, dir_str);
        if (ret != length - 1)
        {
            fprintf(stderr, "Error while building counter name '%s-%s'\n", nft_counter_name, dir_str);
            exit(EXIT_FAILURE);
        }
        if (direction == OUT) {
            packet_count.packets_out = counter_read_packets(nft_table_name, counter);
        } else {
            // direction == IN
            packet_count.packets_in = counter_read_packets(nft_table_name, counter);
        }
    }

    return packet_count;
}

/**
 * @brief Initialize the values of a duration_t structure.
 *
 * @param nft_table_name name of the nftables table containing the associated nftables counter
 * @param nft_counter_name name of the associated nftables counter
 * @return duration_t struct containing the initial duration value
 */
duration_t counter_duration_init() {
    duration_t duration;
    duration.is_initialized = true;
    duration.microseconds = counter_read_microseconds();
    return duration;
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
