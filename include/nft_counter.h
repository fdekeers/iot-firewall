/**
 * @file include/nft_counter.h
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Interface to nftables counters
 * @date 2022-11-02
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _IOTFIREWALL_NFT_COUNTER_
#define _IOTFIREWALL_NFT_COUNTER_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>


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


#endif
