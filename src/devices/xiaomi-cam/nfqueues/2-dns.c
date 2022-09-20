/**
 * @file src/devices/xiaomi-cam/2-dns.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief 
 * @date 2022-09-16
 * 
 * @copyright Copyright (c) 2022
 * 
 */

// Standard libraries
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
// Custom libraries
#include "nfqueue.h"
// Parsers
#include "parsers/header.h"
#include "parsers/dns.h"

#define NFQUEUE_ID 2

/**
 * Current DHCP state
 */
typedef enum {
    INIT,
    QUERIED,
    ANSWERED
} dns_state_t;

dns_state_t state = INIT;

/**
 * @brief Basic callback function, called when a packet enters the queue.
 * 
 * @param pkt_id packet ID for netfilter queue
 * @param payload pointer to the packet payload
 * @param arg pointer to the argument passed to the callback function
 * @return the verdict for the packet
 */
uint32_t callback(int pkt_id, uint8_t *payload, void *arg) {
    printf("Received packet\n");
    // Skip layer 3 and 4 headers
    size_t skipped = get_ip_header_length(payload);
    skipped += get_udp_header_length(payload + skipped);
    // Parse DNS message
    dns_message_t message = dns_parse_message(payload + skipped);
    dns_print_message(message);

    // Match packet application layer
    if (
        state == INIT &&
        message.header.qr == 0 &&
        message.questions->qtype == A &&
        dns_contains_domain_name(message.questions, message.header.qdcount, "business.smartcamera.api.io.mi.com")
    ) {
        state = QUERIED;
        printf("Received query.\n");
    } else if (
        state == QUERIED &&
        message.header.qr == 1
    ) {
        printf("Received answer.\n");
        ip_list_t ip_list = dns_get_ip_from_name(message.answers, message.header.ancount, "business.smartcamera.api.io.mi.com");
        if (ip_list.ip_count > 0) {
            state = ANSWERED;
            printf("IP addresses for business.smartcamera.api.io.mi.com:\n");
            for (uint8_t i = 0; i < ip_list.ip_count; i++) {
                printf("  %s", ipv4_net_to_str(*(ip_list.ip_addresses + i)));
            }
        }
    }

    return NF_ACCEPT;
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