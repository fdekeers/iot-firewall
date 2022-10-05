/**
 * @file src/devices/xiaomi-cam/1-dhcp.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Netfilter queue interface for the 
 * @date 2022-09-14
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
#include "packet_utils.h"
// Parsers
#include "parsers/header.h"
#include "parsers/dhcp.h"

#define NFQUEUE_ID 1  // Netfilter queue ID

/**
 * Current DHCP state
 */
typedef enum {
    INIT,
    DISCOVERED,
    OFFERED,
    REQUESTED,
    ACKED
} dhcp_state_t;

dhcp_state_t state = INIT;

/**
 * @brief Basic callback function, called when a packet enters the queue.
 * 
 * @param pkt_id packet ID for netfilter queue
 * @param payload pointer to the packet payload
 * @param arg pointer to the argument passed to the callback function
 * @return the verdict for the packet
 */
uint32_t callback(int pkt_id, uint8_t *payload, void *arg) {
    // Skip layer 3 and 4 headers
    size_t skipped = get_ip_header_length(payload);
    skipped += get_udp_header_length(payload + skipped);
    // Parse DHCP message
    dhcp_message_t message = dhcp_parse_message(payload + skipped);
    dhcp_print_message(message);
    // Match packet application layer
    if (strcmp(mac_hex_to_str(message.chaddr), "78:8b:2a:b2:20:ea") == 0) {
        if (state == INIT &&
            message.options.message_type == DISCOVER) {
            state = DISCOVERED;
            return NF_ACCEPT;
        } else if (state == DISCOVERED &&
                message.options.message_type == OFFER) {
            state = OFFERED;
            return NF_ACCEPT;
        } else if (state == OFFERED &&
                message.options.message_type == REQUEST) {
            state = REQUESTED;
            return NF_ACCEPT;
        } else if (state == REQUESTED &&
                message.options.message_type == ACK) {
            state = ACKED;
            return NF_ACCEPT;
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
