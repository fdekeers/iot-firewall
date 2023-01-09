/**
 * @file include/rule_utils.h
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Interface to nftables counters
 * @date 2022-11-02
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _IOTFIREWALL_RULE_UTILS_
#define _IOTFIREWALL_RULE_UTILS_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>


// Counter type
typedef enum {
    PACKETS = 1,
    BYTES = 2
} counter_type_t;

// Packet direction
typedef enum {
    BOTH,
    OUT,
    IN
} direction_t;

// Initial counters values
typedef struct {
    bool is_initialized;
    uint16_t packets_out;
    uint16_t packets_in;
    uint16_t packets_both;
    uint64_t microseconds;
} initial_values_t;

// Initial values for packet count
typedef struct {
    bool is_initialized;
    uint16_t packets_both;
    uint16_t packets_out;
    uint16_t packets_in;
} packet_count_t;

// Initial value for duration counter
typedef struct {
    bool is_initialized;
    uint64_t microseconds;
} duration_t;


/**
 * @brief Read the packet count value of an nftables counter.
 *
 * @param table_name name of the nftables table containing the counter
 * @param counter_name name of the nftables counter to read
 * @return packet count value of the counter
 */
uint32_t counter_read_packets(char *table_name, char *counter_name);

/**
 * @brief Read the bytes value of an nftables counter.
 *
 * @param table_name name of the nftables table containing the counter
 * @param counter_name name of the nftables counter to read
 * @return bytes value of the counter
 */
uint32_t counter_read_bytes(char* table_name, char *counter_name);

/**
 * @brief Read the current microseconds value.
 * 
 * @return current microseconds value
 */
uint64_t counter_read_microseconds();

/**
 * @brief Initialize the values of a packet_count_t structure.
 *
 * @param nft_table_name name of the nftables table containing the associated nftables counter
 * @param nft_counter_name name of the associated nftables counter
 * @param direction_idx index of the direction of the rule (0 for both, 1 for out, 2 for in)
 * @return packet_count_t struct containing the initial packet count values
 */
packet_count_t counter_packets_init(char *nft_table_name, char *nft_counter_name, direction_t direction);

/**
 * @brief Initialize the values of a duration_t structure.
 *
 * @param nft_table_name name of the nftables table containing the associated nftables counter
 * @param nft_counter_name name of the associated nftables counter
 * @return duration_t struct containing the initial duration value
 */
duration_t counter_duration_init();

/**
 * @brief Delete an nftables rule.
 *
 * @param nft_table nftables table containing the rule
 * @param nft_chain nftables chain containing the rule
 * @param nft_rule nftables rule to delete
 * @return true if the rule was correctly deleted, false otherwise
 */
bool delete_nft_rule(char *nft_table, char *nft_chain, char *nft_rule);


#endif
