// Standard libraries
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
// Custom libraries
#include "nfqueue.h"

#define NFQ_ID_BASE 10

uint32_t callback(int pkt_id, int pkt_len, uint8_t *payload, void *arg)
{
    printf("Received packet\n");
    return NF_ACCEPT;
}

/**
 * @brief Program entry point
 *
 * @param argc number of command line arguments
 * @param argv list of command line arguments
 * @return exit code, 0 if success
 */
int main(int argc, char const *argv[])
{

    bind_queue(NFQ_ID_BASE, &callback, NULL);

    return 0;
}
