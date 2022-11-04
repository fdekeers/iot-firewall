/**
 * @file include/nfqueue.h
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Wrapper for the netfilter_queue library
 * @date 2022-09-09
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _IOTFIREWALL_NFQUEUE_
#define _IOTFIREWALL_NFQUEUE_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

/**
 * Alias for basic callback function.
 */
typedef uint32_t basic_callback(int pkt_id, uint8_t *payload, void *arg);

/**
 * Structure that stores a basic callback function and its arguments.
 */
typedef struct callback_struct {
    basic_callback *func;  // Basic callback function
    void *arg;             // Arguments to pass to the callback function
} callback_struct_t;

/**
 * @brief Contains the necessary arguments for an nfqueue thread.
 * The arguments are:
 * - the queue number to bind to
 * - the basic callback function
 * - the arguments to pass to the callback function
 */
typedef struct {
    uint8_t thread_id;     // Thread id
    uint16_t queue_id;     // Queue number to bind to
    basic_callback *func;  // Basic callback function
    void *arg;             // Arguments to pass to the callback function
} thread_arg_t;

/**
 * Retrieve the packet id from a nfq_data struct,
 * or -1 in case of error.
 * 
 * @param nfa the given nfq_data struct
 * @return the packet id, or -1 in case of error
 */
int get_pkt_id(struct nfq_data *nfad);

/**
 * Bind queue to callback function,
 * and wait for packets.
 * 
 * @param queue_num the number of the queue to bind to
 * @param callback the callback funtion, called upon packet reception
 * The callback function must have the following signature:
 *     int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
 * @param arg the argument to pass to the callback function
 */
void bind_queue(uint16_t queue_num, basic_callback *callback, void *arg);

/**
 * @brief pthread wrapper for bind_queue.
 * 
 * @param arg typeless pointer to the thread argument, which is a thread_arg_t struct containing the necessary arguments for bind_queue.
 * @return NULL
 */
void* nfqueue_thread(void *arg);


#endif /* _IOTFIREWALL_NFQUEUE_ */
