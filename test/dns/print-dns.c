#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns.h"

int main(int argc, char **argv) {

    char hexstring[] = "6dca8180000100020000000008627573696e6573730b736d61727463616d6572610361706902696f026d6903636f6d0000010001c00c0005000100000258002516636e616d652d6170702d636f6d2d616d7370726f78790177066d692d64756e03636f6d00c04000010001000000930004142f61e7";
    char *pos = hexstring;
    size_t length = strlen(hexstring) / 2;
    unsigned char *val = (unsigned char *) malloc(length);

    // WARNING: no sanitization or error-checking whatsoever
    for (size_t count = 0; count < length; count++) {
        sscanf(pos, "%2hhx", val+count);
        pos += 2;
    }

    /*
    printf("0x");
    for(size_t count = 0; count < length; count++)
        printf("%02x", *(val+count));
    printf("\n");
    */

    dns_message message = dns_parse_message(length, val);
    dns_print_message(message);

    return 0;
}
