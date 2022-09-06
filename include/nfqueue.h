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
 * Bind queue to callback function,
 * and wait for packets.
 * 
 * @param queue_num the number of the queue to bind to
 * @param callback the callback funtion, called upon packet reception
 * The callback function must have the following signature:
 *     int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
 */
void bind_queue(uint16_t queue_num, nfq_callback *callback, void *arg);

/**
 * Retrieve the packet id from a nfq_data struct.
 * 
 * @param nfa the given nfq_data struct
 * @return the packet id
 */
int get_pkt_id(struct nfq_data *nfa);


#endif /* _IOTFIREWALL_NFQUEUE_ */
