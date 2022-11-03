/**
 * @file test/nft_counter.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Unit tests for the interface with nftables counters
 * @date 2022-11-02
 * 
 * @copyright Copyright (c) 2022
 * 
 */

// Custom libraries
#include "nft_counter.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


/**
 * @brief Test the reading of the packets value of an nftables counter.
 */
void test_nft_counter_packets() {
    CU_ASSERT_EQUAL(counter_read_packets("test", "counter1"), 0);
}

/**
 * @brief Test the reading of the bytes value of an nftables counter.
 */
void test_nft_counter_bytes() {
    CU_ASSERT_EQUAL(counter_read_bytes("test", "counter1"), 0);
}

/**
 * Test suite entry point.
 */
int main(int argc, char const *argv[])
{
    // Initialize the nftables table and counter
    system("sudo nft add table test");
    system("sudo nft add counter test counter1");
    // Initialize the CUnit test registry and suite
    printf("Test suite: nft_counter\n");
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("nft_counter", NULL, NULL);
    // Add and run tests
    CU_add_test(suite, "nft_counter_packets", test_nft_counter_packets);
    CU_add_test(suite, "nft_counter_bytes", test_nft_counter_bytes);
    CU_basic_run_tests();
    return 0;
}
