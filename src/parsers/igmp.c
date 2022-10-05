/**
 * @file igmp.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief 
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "igmp.h"


///// PARSING /////

/**
 * @brief Parse an IGMP message.
 * 
 * @param data pointer to the start of the IGMP message
 * @return the parsed IGMP message
 */
igmp_message_t igmp_parse_message(uint8_t *data) {
    igmp_message_t message;
    message.type = *data;
    message.max_resp_time = *(data + 1);
    message.checksum = ntohs(*((uint16_t *) (data + 2)));
    message.group_address = *((uint32_t *) (data + 4));  // Stored in network byte order
    return message;
}


// PRINTING

/**
 * @brief Print an IGMP message.
 * 
 * @param message the IGMP message to print
 */
void igmp_print_message(igmp_message_t message) {
    printf("IGMP message:\n");
    printf("  Type: %#hhx\n", message.type);
    printf("  Max resp time: %hhu\n", message.max_resp_time);
    printf("  Checksum: %hu\n", message.checksum);
    printf("  Group address: %s\n", ipv4_net_to_str(message.group_address));
}
