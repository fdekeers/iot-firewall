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
#include <pthread.h>
#include <assert.h>
// Custom libraries
#include "nfqueue.h"
#include "packet_utils.h"
// Parsers
#include "parsers/header.h"
#include "parsers/dns.h"
#include "parsers/igmp.h"

#define NUM_THREADS 4
#define NFQUEUE_ID_RANGE 10

/**
 * Current state
 */
typedef enum {
    STATE_A,
    STATE_B,
    STATE_C,
    STATE_D,
    STATE_E
} state_t;

state_t state = STATE_A;

/**
 * @brief Basic callback function, called when a packet enters the queue.
 * 
 * @param pkt_id packet ID for netfilter queue
 * @param payload pointer to the packet payload
 * @param arg pointer to the argument passed to the callback function
 * @return the verdict for the packet
 */
uint32_t callback_igmp(int pkt_id, uint8_t *payload, void *arg) {
    // Skip layer 3 and 4 headers
    size_t skipped = get_ip_header_length(payload);

    // Receive IGMP query for mDNS group (224.0.0.251)
    igmp_message_t message = igmp_parse_message(payload + skipped);
    igmp_print_message(message);
    if (
        message.type == V2_MEMBERSHIP_REPORT &&
        message.group_address == ipv4_str_to_net("224.0.0.251")
    ) {
        state = STATE_B;
        printf("IGMP Membership Report for group mDNS\n");
        return NF_ACCEPT;
    }

    return NF_DROP;

    /*
    case STATE_B: {
        // Receive mDNS query for _miio._udp.local or _rc._tcp.local
        dns_message_t message = dns_parse_message(payload + skipped);
        dns_print_message(message);
        if (
            message.header.qr == 0 &&
            message.questions->qtype == PTR &&
            ( dns_contains_domain_name(message.questions, message.header.qdcount, "_miio._udp.local") ||
              dns_contains_domain_name(message.questions, message.header.qdcount, "_rc._tcp.local") )
        ) {
            state = STATE_C;
            printf("mDNS query\n");
            return NF_ACCEPT;
        }
    }
    break;

    case STATE_C: {
        // Receive UDP broadcast from local address to broadcast
        printf("UDP from local address to broadcast\n");
        state = STATE_D;
        return NF_ACCEPT;
    }
    
    case STATE_D: {
        // Receive ARP
        printf("ARP request from camera to local address\n");
        state = STATE_E;
        return NF_ACCEPT;
    }

    default:
        break;
    }
    */
}

/**
 * @brief Program entry point
 * 
 * @param argc number of command line arguments
 * @param argv list of command line arguments
 * @return exit code, 0 if success
 */
int main(int argc, char const *argv[]) {
    // Create threads
    uint8_t i = 0;
    pthread_t threads[NUM_THREADS];
    // IGMP
    thread_arg_t thread_arg_igmp = {
        .queue_id = NFQUEUE_ID_RANGE + i,
        .func = &callback_igmp,
        .arg = NULL
    };
    int ret = pthread_create(&threads[i++], NULL, nfqueue_thread, (void *) &thread_arg_igmp);
    assert(!ret);

    // Wait forever for threads
    for (i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}