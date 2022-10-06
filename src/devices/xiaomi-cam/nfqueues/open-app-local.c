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

#define MAX_THREADS 6
#define NUM_STATES  6
#define NFQUEUE_ID_RANGE 10

/**
 * Represent the current state
 */
typedef enum {
    STATE_A,
    STATE_B,
    STATE_C,
    STATE_D,
    STATE_E,
    STATE_F
} state_t;

// Global variables
state_t state = STATE_A;  // Initial state
uint8_t num_threads = 0;  // Current number of threads
pthread_mutex_t mutex;    // Mutex to protect the state

/**
 * @brief Callback function for the IGMP Membership Report (first queue).
 * 
 * @param pkt_id packet ID for netfilter queue
 * @param payload pointer to the packet payload
 * @param arg pointer to the argument passed to the callback function
 * @return the verdict for the packet (NF_ACCPET or NF_DROP)
 */
uint32_t callback_igmp(int pkt_id, uint8_t *payload, void *arg) {
    // Skip IP header
    size_t skipped = get_ip_header_length(payload);

    // Receive IGMP query for mDNS group (224.0.0.251)
    igmp_message_t message = igmp_parse_message(payload + skipped);
    igmp_print_message(message);
    uint32_t verdict = NF_DROP;
    if (
        message.type == V2_MEMBERSHIP_REPORT &&
        message.group_address == ipv4_str_to_net("224.0.0.251")
    ) {
        pthread_mutex_lock(&mutex);
        if (state == STATE_A) {
            state = STATE_B;
            pthread_mutex_unlock(&mutex);
            printf("IGMP Membership Report for group mDNS\n");
            verdict = NF_ACCEPT;
        } else {
            pthread_mutex_unlock(&mutex);
        }
    }

    return verdict;
}

/**
 * @brief Callback function for the mDNS query (second queue).
 * 
 * @param pkt_id packet ID for netfilter queue
 * @param payload pointer to the packet payload
 * @param arg pointer to the argument passed to the callback function
 * @return the verdict for the packet (NF_ACCPET or NF_DROP)
 */
uint32_t callback_mdns(int pkt_id, uint8_t *payload, void *arg) {
    // Skip IP and UDP headers
    size_t skipped = get_ip_header_length(payload);
    skipped += get_udp_header_length(payload + skipped);

    // Receive mDNS query for _miio._udp.local or _rc._tcp.local
    dns_message_t message = dns_parse_message(payload + skipped);
    dns_print_message(message);
    uint32_t verdict = NF_DROP;
    if (
        message.header.qr == 0 &&
        message.questions->qtype == PTR &&
        ( dns_contains_domain_name(message.questions, message.header.qdcount, "_miio._udp.local") ||
          dns_contains_domain_name(message.questions, message.header.qdcount, "_rc._tcp.local") )
    ) {
        pthread_mutex_lock(&mutex);
        if (state == STATE_B) {
            state = STATE_C;
            pthread_mutex_unlock(&mutex);
            printf("mDNS query\n");
            verdict = NF_ACCEPT;
        } else {
            pthread_mutex_unlock(&mutex);
        }
    }

    return verdict;
}

/**
 * @brief Callback function for the UDP broadcast (third queue).
 * 
 * @param pkt_id packet ID for netfilter queue
 * @param payload pointer to the packet payload
 * @param arg pointer to the argument passed to the callback function
 * @return the verdict for the packet (NF_ACCPET or NF_DROP)
 */
uint32_t callback_udp_broadcast(int pkt_id, uint8_t *payload, void *arg) {
    uint32_t verdict = NF_DROP;
    pthread_mutex_lock(&mutex);
    if (state == STATE_C) {
        state = STATE_D;
        pthread_mutex_unlock(&mutex);
        printf("UDP broadcast\n");
        verdict = NF_ACCEPT;
    } else {
        pthread_mutex_unlock(&mutex);
    }

    return verdict;
}

/**
 * @brief Callback function for the ARP request (fourth queue).
 * 
 * @param pkt_id packet ID for netfilter queue
 * @param payload pointer to the packet payload
 * @param arg pointer to the argument passed to the callback function
 * @return the verdict for the packet (NF_ACCPET or NF_DROP)
 */
uint32_t callback_arp_request(int pkt_id, uint8_t *payload, void *arg) {
    uint32_t verdict = NF_DROP;
    pthread_mutex_lock(&mutex);
    if (state == STATE_D) {
        state = STATE_E;
        pthread_mutex_unlock(&mutex);
        printf("ARP request for phone IP\n");
        verdict = NF_ACCEPT;
    } else {
        pthread_mutex_unlock(&mutex);
    }

    return verdict;
}

/**
 * @brief Callback function for the ARP reply (fifth queue).
 * 
 * Add the next nftables rule to the chain, which is
 * for burst and background UDP traffic.
 * 
 * @param pkt_id packet ID for netfilter queue
 * @param payload pointer to the packet payload
 * @param arg pointer to the argument passed to the callback function
 * @return the verdict for the packet (NF_ACCPET or NF_DROP)
 */
uint32_t callback_arp_reply(int pkt_id, uint8_t *payload, void *arg) {
    uint32_t verdict = NF_DROP;
    pthread_mutex_lock(&mutex);
    if (state == STATE_E) {
        state = STATE_F;
        pthread_mutex_unlock(&mutex);
        printf("ARP reply for phone IP\n");
        // Add UDP traffic rules
        system("nft add rule netdev xiaomi-cam open-app-local ip saddr 192.168.1.161 ip daddr 192.168.1.0/24 limit rate 10/second burst 20 packets meta length >= 40 meta length <= 300");
        system("nft add rule netdev xiaomi-cam open-app-local ip saddr 192.168.1.161 ip daddr 192.168.1.0/24 limit rate 10/second burst 20 packets meta length >= 40 meta length <= 300");
        verdict = NF_ACCEPT;
    } else {
        pthread_mutex_unlock(&mutex);
    }

    return verdict;
}

/**
 * @brief Program entry point
 * 
 * @param argc number of command line arguments
 * @param argv list of command line arguments
 * @return exit code, 0 if success
 */
int main(int argc, char const *argv[]) {
    // Initialize mutex for state
    int ret = pthread_mutex_init(&mutex, NULL);
    assert(ret == 0);

    // Create threads
    uint8_t i = 0;
    pthread_t threads[MAX_THREADS];

    // IGMP
    thread_arg_t thread_arg_igmp = {
        .queue_id = NFQUEUE_ID_RANGE + i,
        .func = &callback_igmp,
        .arg = NULL
    };
    ret = pthread_create(&threads[i++], NULL, nfqueue_thread, (void *) &thread_arg_igmp);
    assert(ret == 0);

    // mDNS
    thread_arg_t thread_arg_mdns = {
        .queue_id = NFQUEUE_ID_RANGE + i,
        .func = &callback_mdns,
        .arg = NULL
    };
    ret = pthread_create(&threads[i++], NULL, nfqueue_thread, (void *) &thread_arg_mdns);
    assert(ret == 0);

    // UDP broadcast
    thread_arg_t thread_arg_udp_broadcast = {
        .queue_id = NFQUEUE_ID_RANGE + i,
        .func = &callback_udp_broadcast,
        .arg = NULL
    };
    ret = pthread_create(&threads[i++], NULL, nfqueue_thread, (void *) &thread_arg_udp_broadcast);
    assert(ret == 0);

    // ARP request
    thread_arg_t thread_arg_arp_request = {
        .queue_id = NFQUEUE_ID_RANGE + i,
        .func = &callback_arp_request,
        .arg = NULL
    };
    ret = pthread_create(&threads[i++], NULL, nfqueue_thread, (void *) &thread_arg_arp_request);
    assert(ret == 0);

    // ARP reply
    thread_arg_t thread_arg_arp_reply = {
        .queue_id = NFQUEUE_ID_RANGE + i,
        .func = &callback_arp_reply,
        .arg = NULL
    };
    ret = pthread_create(&threads[i++], NULL, nfqueue_thread, (void *) &thread_arg_arp_reply);
    assert(ret == 0);

    // Wait forever for threads
    for (i = 0; i < MAX_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    // Destroy mutex
    pthread_mutex_destroy(&mutex);

    return 0;
}
