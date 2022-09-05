#include "packet-utils.h"


/**
 * Print a packet payload.
 * 
 * @param length length of the payload in bytes
 * @param data pointer to the start of the payload
 */
void print_payload(int length, unsigned char *data) {
    char trailing = ' ';
	// Iterate on the whole payload
	for (int i = 0; i < length; i++) {
        if (i == length - 1) {
            // Insert newline after last byte
            trailing = '\n';
        }

		unsigned char c = *(data + i);
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
size_t hexstr_to_payload(char *hexstring, unsigned char **payload) {
    size_t length = strlen(hexstring) / 2;  // Size of the payload in bytes, one byte is two characters
    *payload = (unsigned char *) malloc(length * sizeof(unsigned char));  // Allocate memory for the payload

    // WARNING: no sanitization or error-checking whatsoever
    for (size_t count = 0; count < length; count++) {
        sscanf(hexstring + 2*count, "%2hhx", (*payload) + count);  // Convert two characters to one byte
    }

    return length;
}
