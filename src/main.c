#include <stdlib.h>
#include <stdio.h>
// Custom libraries
#include "hashmap.h"
#include "nfqueue.h"
// Parsers
#include "parsers/header.h"
#include "parsers/dns.h"


static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    int pkt_id = get_pkt_id(nfa);

    return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, NULL);
}


int main(int argc, char const *argv[])
{
    // Bind to nfqueue queue 0
    bind_queue(0, &callback);

    return EXIT_SUCCESS;
}
