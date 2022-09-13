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
#include <string.h>
#include <arpa/inet.h>

#define MAC_ADDRESS_LEN       6
#define MAX_HW_LEN            16
#define DHCP_HEADER_LEN       236
#define DHCP_MAX_OPTION_COUNT 20
#define DHCP_MAGIC_COOKIE     0x63825363


////////// TYPE DEFINITIONS //////////

/**
 * DHCP opcode
 */
typedef enum {
    BOOTREQUEST = 1,
    BOOTREPLY = 2
} dhcp_opcode;

typedef enum {
    PAD = 0,
    END = 255
} dhcp_option_code;

/**
 * DHCP Option
 */
typedef struct dhcp_option {
    uint8_t code;
    uint8_t length;
    uint8_t *value;
} dhcp_option;

/**
 * DHCP Options
 */
typedef struct dhcp_options {
    uint8_t count;         // Number of options
    dhcp_option *options;  // List of options
} dhcp_options;

/**
 * DHCP Message
 */
typedef struct dhcp_message {
    uint8_t op;            // DHCP opcode
    uint8_t htype;         // Hardware address type
    uint8_t hlen;          // Hardware address length
    uint8_t hops;          // Number of hops
    uint32_t xid;          // Transaction ID
    uint16_t secs;         // Seconds elapsed since client began address acquisition or renewal process
    uint16_t flags;        // DHCP flags
    uint32_t ciaddr;       // Client IP address
    uint32_t yiaddr;       // Your (client) IP address
    uint32_t siaddr;       // Next server IP address
    uint32_t giaddr;       // Relay agent IP address
    uint8_t chaddr[16];    // Client hardware address
    uint8_t sname[64];     // Optional server host name
    uint8_t file[128];     // Boot file name
    dhcp_options options;  // DHCP options
} dhcp_message;


////////// FUNCTIONS //////////

///// PARSING /////

/**
 * @brief Parse the header of a DHCP message (not including options)
 * 
 * @param data a pointer to the start of the DHCP message
 * @return the parsed DHCP message with the header fields filled in
 */
dhcp_message dhcp_parse_header(uint8_t *data);

/**
 * @brief Parse a DHCP option
 * 
 * @param data a pointer to the start of the DHCP option
 * @param offset a pointer to the current offset inside the DHCP message
 *               Its value will be updated to point to the next option
 * @return the parsed DHCP option
 */
dhcp_option dhcp_parse_option(uint8_t *data, uint16_t *offset);

/**
 * @brief Parse DHCP options
 * 
 * @param data a pointer to the start of the DHCP options list
 * @return a pointer to the start of the parsed DHCP options
 */
dhcp_options dhcp_parse_options(uint8_t *data);

/**
 * @brief Parse a DHCP message
 * 
 * @param data a pointer to the start of the DHCP message
 * @return the parsed DHCP message
 */
dhcp_message dhcp_parse_message(uint8_t *data);


///// PRINTING /////

/**
 * @brief Print the header of a DHCP message
 * 
 * @param message the DHCP message to print the header of
 */
void dhcp_print_header(dhcp_message message);

/**
 * @brief Print a DHCP option
 * 
 * @param option the DHCP option to print
 */
void dhcp_print_option(dhcp_option option);

/**
 * @brief Print a DHCP message
 * 
 * @param message the DHCP message to print
 */
void dhcp_print_message(dhcp_message message);


#endif /* _IOTFIREWALL_DHCP_ */
