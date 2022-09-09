#ifndef _IOTFIREWALL_PACKET_UTILS_
#define _IOTFIREWALL_PACKET_UTILS_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


/**
 * Print a packet payload.
 * 
 * @param length length of the payload in bytes
 * @param data pointer to the start of the payload
 */
void print_payload(int length, unsigned char *data);

/**
 * Converts a hexstring payload to a data buffer.
 * 
 * @param hexstring the hexstring to convert
 * @param payload a double pointer to the payload, which will be set to the start of the payload
 * @return the length of the payload in bytes
 */
size_t hexstr_to_payload(char *hexstring, unsigned char **payload);

/**
 * Converts an IPv4 addres from its hexadecimal representation
 * to its string representation.
 * 
 * @param ipv4_hex IPv4 address in hexadecimal representation
 * @return the same IPv4 address in string representation
 */
char* ipv4_hex_to_str(char* ipv4_hex);

/**
 * Converts an IPv4 addres from its string representation
 * to its hexadecimal representation.
 * 
 * @param ipv4_str IPv4 address in string representation
 * @return the same IPv4 address in hexadecimal representation
 */
char* ipv4_str_to_hex(char* ipv4_str);


#endif /* _IOTFIREWALL_PACKET_UTILS_ */
