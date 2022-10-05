/**
 * @file include/parsers/igmp.h
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief IGMP message parser
 * @date 2022-10-05
 * 
 * IGMP message parser.
 * Currently only supports v1 and v2.
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _IOTFIREWALL_IGMP_
#define _IOTFIREWALL_IGMP_

#include <stdio.h>
#include <stdint.h>
#include "packet_utils.h"


/**
 * @brief IGMP message types
 */
typedef enum {
    MEMBERSHIP_QUERY     = 0x11,
    V1_MEMBERSHIP_REPORT = 0x12,
    V2_MEMBERSHIP_REPORT = 0x16,
    LEAVE_GROUP          = 0x17,
    V3_MEMBERSHIP_REPORT = 0x22
} igmp_message_type_t;

/**
 * @brief IGMP message
 */
typedef struct {
    igmp_message_type_t type;
    uint8_t max_resp_time;
    uint16_t checksum;
    uint32_t group_address;  // IPv4 group address, in network byte order
} igmp_message_t;


////////// FUNCTIONS //////////

///// PARSING /////

/**
 * @brief Parse an IGMP message.
 * 
 * @param data pointer to the start of the IGMP message
 * @return the parsed IGMP message
 */
igmp_message_t igmp_parse_message(uint8_t *data);


///// PRINTING /////

/**
 * @brief Print an IGMP message.
 * 
 * @param message the IGMP message to print
 */
void igmp_print_message(igmp_message_t message);


#endif /* _IOTFIREWALL_IGMP_ */
