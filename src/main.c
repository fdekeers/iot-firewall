#include <stdlib.h>
#include <stdio.h>
#include <hashmap.h>
#include "parsers/dns.h"

int main(int argc, char const *argv[])
{
    printf("Hello, World!\n");
    dns_header header;
    header.id = 1;
    header.flags = 0;
    header.qdcount = 1;
    header.ancount = 1;
    header.nscount = 0;
    header.arcount = 0;
    dns_print_header(header);
    return 0;
}
