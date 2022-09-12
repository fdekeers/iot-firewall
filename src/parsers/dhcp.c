/**
 * @file /parsers/dhcp.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief DHCP message parser
 * @date 2022-09-12
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "parsers/dhcp.h"

///// PARSING /////

/**
 * @brief Parse a DHCP message
 * 
 * @param data a pointer to the start of the DHCP message
 * @return the parsed DHCP message
 */
dhcp_message dhcp_parse_message(uint8_t *data) {
    // Parse constant fields
    dhcp_message message = dhcp_parse_header(data);
    // Parse DHCP options
    message.options = dhcp_parse_options(data);
    // Return
    return message;
}

/**
 * @brief Parse the header of a DHCP message (not including options)
 * 
 * @param data a pointer to the start of the DHCP message
 * @return the parsed DHCP message with the header fields filled in
 */
dhcp_message dhcp_parse_header(uint8_t *data) {
    dhcp_message message;
    // Opcode: 1 byte
    message.op = *data;
    // htype: 1 byte
    message.htype = *(data + 1);
    // hlen: 1 byte
    message.hlen = *(data + 2);
    // hops: 1 byte
    message.hops = *(data + 3);
    // xid: 4 bytes
    message.xid = ntohl(*((uint32_t *) (data + 4)));
    // secs: 2 bytes
    message.secs = ntohs(*((uint16_t *) (data + 8)));
    // flags: 2 bytes
    message.flags = ntohs(*((uint16_t *) (data + 10)));
    // ciaddr: 4 bytes
    message.ciaddr = ntohl(*((uint32_t *) (data + 12)));
    // yiaddr: 4 bytes
    message.yiaddr = ntohl(*((uint32_t *) (data + 16)));
    // siaddr: 4 bytes
    message.siaddr = ntohl(*((uint32_t *) (data + 20)));
    // giaddr: 4 bytes
    message.giaddr = ntohl(*((uint32_t *) (data + 24)));
    // chaddr: 16 bytes
    memcpy(message.chaddr, data + 28, sizeof(uint8_t) * 16);
    // sname: 64 bytes
    memcpy(message.sname, data + 44, sizeof(uint8_t) * 64);
    // file: 128 bytes
    memcpy(message.file, data + 108, sizeof(uint8_t) * 128);
    // DHCP options
    message.options = dhcp_parse_options(data + DHCP_HEADER_SIZE);
    return message;
}

/**
 * @brief Parse DHCP options
 * 
 * @param data a pointer to the start of the DHCP options list
 * @return a pointer to the start of the parsed DHCP options
 * 
 * TODO: realloc if too many options
 */
dhcp_options dhcp_parse_options(uint8_t *data) {
    // Init
    dhcp_options options;
    options.count = 0;
    options.options = (dhcp_option *) malloc(sizeof(dhcp_option) * DHCP_MAX_OPTION_COUNT);
    // Parse options
}

/**
 * @brief Parse a DHCP option
 * 
 * @param data a pointer to the start of the DHCP option
 * @return the parsed DHCP option
 */
dhcp_option dhcp_parse_option(uint8_t *data) {
    dhcp_option option;
    option.code = *data;
    if (option.code == PAD || option.code == END) {
        option.length = 0;
        option.value = NULL;
    } else {
        option.length = *(data + 1);
        option.value = data + 2;
    }
}


///// PRINTING /////

/**
 * @brief Print a DHCP message
 * 
 * @param message the DHCP message to print
 */
void dhcp_print_message(dhcp_message message);

/**
 * @brief Print a DHCP option
 * 
 * @param option the DHCP option to print
 */
void dhcp_print_option(dhcp_option option);
