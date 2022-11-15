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


// Initial counters values
typedef struct {
    bool is_initialized;
    uint16_t packets_out;
    uint16_t packets_in;
    uint16_t packets_both;
    uint64_t microseconds;
} initial_values_t;


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
 * @brief Initialize counters values.
 *
 * @param nft_table_name name of the nftables table containing the associated nftables counter
 * @param nft_counter_name name of the associated nftables counter
 * @return initial_values_t struct containing the initial values
 */
initial_values_t counters_init(char *nft_table_name, char *nft_counter_name);

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
