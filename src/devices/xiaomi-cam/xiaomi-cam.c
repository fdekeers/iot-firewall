/**
 * @file test/devices/xiaomi-cam/xiaomi-cam.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Netfilter queue interface for the Xiaomi camera
 * @date 2022-09-14
 * 
 * @copyright Copyright (c) 2022
 * 
 */

// Custom libraries
#include "nfqueue.h"
#include "map_domain_ip.h"
// Parsers
#include "parsers/header.h"
#include "parsers/dns.h"
#include "parsers/dhcp.h"

#define NFQUEUE_ID 1  // Netfilter queue ID


/**
 * @brief Callback function, called when a packet enters the queue.
 */
static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    // Get packet id
    int pkt_id = get_pkt_id(nfa);
    // Get packet payload
    uint8_t *payload;
    int length = nfq_get_payload(nfa, &payload);
    if (length >= 0) {
        // Skip layer 3 and 4 headers
        size_t skipped = get_ip_header_length(payload);
        skipped += get_udp_header_length(payload + skipped);
        // Parse DHCP message
        dhcp_message message = dhcp_parse_message(payload + skipped);
        // Print DHCP message
        dhcp_print_message(message);
        // Add nftables rules
    }

    return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, length, payload);
}

/**
 * @brief Program entry point
 * 
 * @param argc number of command line arguments
 * @param argv list of command line arguments
 * @return exit code, 0 if success
 */
int main(int argc, char const *argv[]) {
    // Bind to netfilter queue
    bind_queue(NFQUEUE_ID, &callback, NULL);

    return 0;
}

