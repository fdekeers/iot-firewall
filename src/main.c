/**
 * @file src/main.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Program entry point
 * @date 2022-09-06
 * 
 * @copyright Copyright (c) 2022
 * 
 */

// Standard libraries
#include <stdlib.h>
#include <stdio.h>
// Custom libraries
#include "nfqueue.h"
#include "map_domain_ip.h"
// Parsers
#include "parsers/header.h"
#include "parsers/dns.h"


static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    // Cast DNS map
    map_domain_ip *map = (map_domain_ip*) data;
    // Get packet id
    int pkt_id = get_pkt_id(nfa);
    // Get packet payload
    uint8_t *payload;
    int length = nfq_get_payload(nfa, &payload);
    if (length >= 0) {
        // Skip layer 3 and 4 headers
        size_t skipped = get_ip_header_length(payload);
        skipped += get_udp_header_length(payload + skipped);
        // Parse DNS message
        dns_message message = dns_parse_message(payload + skipped);
        // Add domain names and IP addresses to DNS map
        char** ip_addresses = (char **) malloc(sizeof(char *) * message.header.ancount);
        char* domain_name;
        for (int i = 0; i < message.header.ancount; i++) {
            dns_resource_record rr = *(message.answers + i);
            if (rr.rtype == A) {
                domain_name = rr.name;
                dns_print_rr("Answer", rr);
                *(ip_addresses + i) = rr.rdata;
            }
        }
        map_domain_ip_add(map, domain_name, message.header.ancount, ip_addresses);
    }

    return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, NULL);
}


int main(int argc, char const *argv[])
{
    // Initialize DNS map
    map_domain_ip *map = map_domain_ip_create();

    // Bind to nfqueue queue 0
    bind_queue(0, &callback, map);

    // Destroy DNS map
    map_domain_ip_destroy(map);
    
    return EXIT_SUCCESS;
}
