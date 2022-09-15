/**
 * @file test/devices/xiaomi-cam/xiaomi-cam.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Netfilter queue interface for the Xiaomi camera
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
#include "map_domain_ip.h"
// Parsers
#include "parsers/header.h"
#include "parsers/dns.h"
#include "parsers/dhcp.h"


/**
 * @brief Basic callback function, called when a packet enters the queue.
 */
uint32_t callback_1(int pkt_id, uint8_t *payload, void *arg) {
    // Skip layer 3 and 4 headers
    size_t skipped = get_ip_header_length(payload);
    skipped += get_udp_header_length(payload + skipped);
    // Parse DHCP message
    dhcp_message message = dhcp_parse_message(payload + skipped);
    // Add nftables rules
    if (message.options.message_type == DISCOVER &&
        strcmp(mac_hex_to_str(message.chaddr), "78:8b:2a:b2:20:ea") == 0) {
        dhcp_print_message(message);
        // Add nftables rules
        int ret = system("nft add rule xiaomi-cam dhcp-boot ip saddr 192.168.1.1 ip daddr 192.168.1.161 udp sport 67 udp sport 67 queue num 2");
        if (ret != 0) {
            fprintf(stderr, "Error while adding nftables rule\n");
        }
    }
    return NF_ACCEPT;
}

/**
 * @brief Callback function, called when a packet enters the queue.
 */
/*
static int callback_2(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
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
        // Add nftables rules
        if (message.options.message_type == OFFER &&
            strcmp(mac_hex_to_str(message.chaddr), "78:8b:2a:b2:20:ea") == 0) {
            dhcp_print_message(message);
        }
    }
    return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, length, payload);
}*/

/**
 * @brief Program entry point
 * 
 * @param argc number of command line arguments
 * @param argv list of command line arguments
 * @return exit code, 0 if success
 */
int main(int argc, char const *argv[]) {
    // Bind to netfilter queue
    bind_queue(1, &callback_1, NULL);
    //bind_queue(2, &callback_2, NULL);

    return 0;
}
