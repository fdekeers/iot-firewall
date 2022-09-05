#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CUnit/CUnit.h>
#include "packet-utils.h"
#include "parsers/header.h"
#include "parsers/dns.h"


int main(int argc, char **argv) {

    char *hexstring = "450000912ecc40004011879dc0a80101c0a801a10035a6b5007d76b46dca8180000100020000000008627573696e6573730b736d61727463616d6572610361706902696f026d6903636f6d0000010001c00c0005000100000258002516636e616d652d6170702d636f6d2d616d7370726f78790177066d692d64756e03636f6d00c04000010001000000930004142f61e7";
    
    unsigned char *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);

    print_payload(length, payload);

    payload = skip_headers(payload);
    dns_message message = dns_parse_message(length, payload);
    dns_print_message(message);

    return 0;
}
