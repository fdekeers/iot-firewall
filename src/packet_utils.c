/**
 * @file src/packet_utils.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Utilitaries for payload manipulation and display
 * @date 2022-09-09
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "packet_utils.h"


/**
 * Print a packet payload.
 * 
 * @param length length of the payload in bytes
 * @param data pointer to the start of the payload
 */
void print_payload(int length, uint8_t *data) {
    char trailing = ' ';
	// Iterate on the whole payload
	for (int i = 0; i < length; i++) {
        if (i == length - 1) {
            // Insert newline after last byte
            trailing = '\n';
        }

		uint8_t c = *(data + i);
		if (c == 0) {
			printf("0x00%c", trailing);
		} else {
			printf("%#.2x%c", c, trailing);
		}
	}
}

/**
 * Converts a hexstring payload to a data buffer.
 * 
 * @param hexstring the hexstring to convert
 * @param payload a double pointer to the payload, which will be set to the start of the payload
 * @return the length of the payload in bytes
 */
size_t hexstr_to_payload(char *hexstring, uint8_t **payload) {
    size_t length = strlen(hexstring) / 2;  // Size of the payload in bytes, one byte is two characters
    *payload = (uint8_t *) malloc(length * sizeof(uint8_t));  // Allocate memory for the payload

    // WARNING: no sanitization or error-checking whatsoever
    for (size_t count = 0; count < length; count++) {
        sscanf(hexstring + 2*count, "%2hhx", (*payload) + count);  // Convert two characters to one byte
    }

    return length;
}

/**
 * Converts an IPv4 addres from its hexadecimal representation
 * to its string representation.
 * 
 * @param ipv4_hex IPv4 address in hexadecimal representation
 * @return the same IPv4 address in string representation
 */
char* ipv4_hex_to_str(char* ipv4_hex) {
    char* ipv4_str = (char *) malloc(16 * sizeof(char));  // A string representation of an IPv4 address is at most 15 characters long + null terminator
    int ret = snprintf(ipv4_str, 15, "%hhu.%hhu.%hhu.%hhu", *ipv4_hex, *(ipv4_hex + 1), *(ipv4_hex + 2), *(ipv4_hex + 3));
    // Error handling
    if (ret < 0) {
        fprintf(stderr, "Error converting IPv4 address \\x%2x\\x%2x\\x%2x\\x%2x to string representation.\n", *ipv4_hex, *(ipv4_hex + 1), *(ipv4_hex + 2), *(ipv4_hex + 3));
        exit(EXIT_FAILURE);
    }
    return ipv4_str;
}

/**
 * Converts an IPv4 addres from its string representation
 * to its hexadecimal representation.
 * 
 * @param ipv4_str IPv4 address in string representation
 * @return the same IPv4 address in hexadecimal representation
 */
char* ipv4_str_to_hex(char* ipv4_str) {


    char* ipv4_hex = (char *) malloc(4 * sizeof(char));  // An IPv4 address is 4 bytes long 
    int ret = sscanf(ipv4_str, "%hhu.%hhu.%hhu.%hhu", ipv4_hex, ipv4_hex + 1, ipv4_hex + 2, ipv4_hex + 3);
    // Error handling
    if (ret != 4) {
        fprintf(stderr, "Error converting IPv4 address %s to hexadecimal representation.\n", ipv4_str);
        exit(EXIT_FAILURE);
    }
    return ipv4_hex;
}
