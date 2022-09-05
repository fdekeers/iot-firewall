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
 */
void bind_queue(uint16_t queue_num, nfq_callback *callback);


#endif
