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
#include "dns_table.h"
// Parsers
#include "parsers/header.h"
#include "parsers/dns.h"


static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    // Cast DNS table
    dns_table *table = (dns_table*) data;
    // Get packet id
    int pkt_id = get_pkt_id(nfa);
    // Get packet payload
    unsigned char *payload;
    int length = nfq_get_payload(nfa, &payload);
    if (length >= 0) {
        // Skip layer 3 and 4 headers
        size_t skipped = skip_ip_header(&payload);
        skipped += skip_udp_header(&payload);
        // Parse DNS message
        dns_message message = dns_parse_message(length - skipped, payload);
        // Print IP address in answer
        for (int i = 0; i < message.header.ancount; i++) {
            dns_resource_record rr = *(message.answers + i);
            if (rr.type == A) {
                dns_print_rr("Answer", rr);
                dns_table_add(table, rr.name, rr.rdata);
            }
        }
    }

    return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, NULL);
}


int main(int argc, char const *argv[])
{
    // Initialize DNS table
    dns_table *table = dns_table_create();

    // Bind to nfqueue queue 0
    bind_queue(0, &callback, table);

    // Destroy DNS table
    dns_table_destroy(table);
    
    return EXIT_SUCCESS;
}
