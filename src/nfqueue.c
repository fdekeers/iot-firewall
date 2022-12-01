/**
 * @file src/nfqueue.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Wrapper for the netfilter_queue library
 * @date 2022-09-09
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "nfqueue.h"


/**
 * Retrieve the packet id from a nfq_data struct,
 * or -1 in case of error.
 * 
 * @param nfa the given nfq_data struct
 * @return the packet id, or -1 in case of error
 */
int get_pkt_id(struct nfq_data *nfad) {
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
	if (ph) {
		return ntohl(ph->packet_id);
	}
	return -1;
}

/**
 * @brief Full callback function, compliant to the nfq_callback type.
 * 
 * @param qh queue handle
 * @param nfmsg message object that contains the packet
 * @param nfad Netlink packet data handle
 * @param data data to be used by the function.
 *             In this case, a pointer to a callback_struct_t, which contains a basic_callback function and its arguments.
 * @return -1 on error, >= 0 otherwise
 */
int nfqueue_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data) {
	// Verdict (will be updated by the basic callback function)
	uint32_t verdict = NF_ACCEPT;
	// Get packet id
    int pkt_id = get_pkt_id(nfad);
    // Get packet payload
    uint8_t *payload;
    int length = nfq_get_payload(nfad, &payload);
    if (length >= 0) {
		verdict = (*(((callback_struct_t *) data)->func))(pkt_id, length, payload, ((callback_struct_t *) data)->arg);
	}
	return nfq_set_verdict(qh, pkt_id, verdict, length, payload);
}

/**
 * Bind queue to callback function,
 * and wait for packets.
 * 
 * @param queue_num the number of the queue to bind to
 * @param callback the basic callback funtion, called upon packet reception
 * The callback function must have the following signature:
 *     uint32_t callback(int pkt_id, uint8_t *payload, void *arg)
 * @param arg the argument to pass to the basic callback function
 */
void bind_queue(uint16_t queue_num, basic_callback *callback, void *arg)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));


	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%d'\n", queue_num);
	// Create nfqueue callback function from basic callback function
	callback_struct_t callback_struct;
	callback_struct.func = callback;
	callback_struct.arg = arg;
	qh = nfq_create_queue(h, queue_num, &nfqueue_callback, &callback_struct);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("setting flags to request UID and GID\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve process UID/GID.\n");
	}

	printf("setting flags to request security context\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve security context.\n");
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	while (1) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue %d\n", queue_num);
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);
}

/**
 * @brief pthread wrapper for bind_queue.
 * 
 * @param arg typeless pointer to the thread argument, which is a thread_arg_t struct containing the necessary arguments for bind_queue.
 * @return NULL (should loop forever)
 */
void* nfqueue_thread(void *arg) {
	thread_arg_t *thread_arg = (thread_arg_t *) arg;
	bind_queue(thread_arg->queue_id, thread_arg->func, thread_arg->arg);
	return NULL;
}
