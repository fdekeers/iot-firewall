/**
 * @file include/packet_utils.h
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Utilitaries for payload manipulation and display
 * @date 2022-09-09
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _IOTFIREWALL_PACKET_UTILS_
#define _IOTFIREWALL_PACKET_UTILS_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>


/**
 * Print a packet payload.
 * 
 * @param length length of the payload in bytes
 * @param data pointer to the start of the payload
 */
void print_payload(int length, uint8_t *data);

/**
 * Converts a hexstring payload to a data buffer.
 * 
 * @param hexstring the hexstring to convert
 * @param payload a double pointer to the payload, which will be set to the start of the payload
 * @return the length of the payload in bytes
 */
size_t hexstr_to_payload(char *hexstring, uint8_t **payload);

/**
 * Converts an IPv4 address from its network order numerical representation
 * to its string representation.
 * (Wrapper arount inet_ntoa)
 * 
 * @param ipv4_net IPv4 address in hexadecimal representation
 * @return the same IPv4 address in string representation
 */
char* ipv4_net_to_str(uint32_t ipv4_net);

/**
 * Converts an IPv4 address from its string representation
 * to its network order numerical representation.
 * (Wrapper arount inet_aton)
 * 
 * @param ipv4_str IPv4 address in string representation
 * @return the same IPv4 address in network order numerical representation
 */
uint32_t ipv4_str_to_net(char* ipv4_str);

/**
 * Converts an IPv4 addres from its hexadecimal representation
 * to its string representation.
 * 
 * @param ipv4_hex IPv4 address in hexadecimal representation
 * @return the same IPv4 address in string representation
 */
char* ipv4_hex_to_str(char* ipv4_hex);

/**
 * Converts an IPv4 address from its string representation
 * to its hexadecimal representation.
 * 
 * @param ipv4_str IPv4 address in string representation
 * @return the same IPv4 address in hexadecimal representation
 */
char* ipv4_str_to_hex(char* ipv4_str);


#endif /* _IOTFIREWALL_PACKET_UTILS_ */
