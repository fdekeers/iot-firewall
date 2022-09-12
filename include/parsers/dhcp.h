/**
 * @file include/parsers/dhcp.h
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief DHCP message parser
 * @date 2022-09-12
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _IOTFIREWALL_DHCP_
#define _IOTFIREWALL_DHCP_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>


////////// TYPE DEFINITIONS //////////

/**
 * DHCP Message
 */
typedef struct dhcp_message {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint32_t magic_cookie;
    uint8_t options[308];
} dhcp_message;



////////// FUNCTIONS //////////

///// PARSING /////




///// PRINTING /////



#endif /* _IOTFIREWALL_DHCP_ */
