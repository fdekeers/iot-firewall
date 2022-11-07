/**
 * @file test/counters.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Unit tests for the interface with nftables counters
 * @date 2022-11-02
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>
// Custom libraries
#include "counters.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


/**
 * @brief Test the reading of the packets value of an nftables counter.
 */
void test_counter_read_packets()
{
    CU_ASSERT_EQUAL(counter_read_packets("test", "counter1"), 0);
}

/**
 * @brief Test the reading of the bytes value of an nftables counter.
 */
void test_counter_read_bytes()
{
    CU_ASSERT_EQUAL(counter_read_bytes("test", "counter1"), 0);
}

void test_counter_read_microseconds() {
    // Retrieve time before calling function under test
    struct timeval tv;
    int ret = gettimeofday(&tv, NULL);
    if (ret != 0)
    {
        perror("gettimeofday");
        exit(EXIT_FAILURE);
    }
    uint64_t timestamp = ((uint64_t)tv.tv_sec) * 1000000 + ((uint64_t)tv.tv_usec);
    // Call function under test
    CU_ASSERT(counter_read_microseconds() > timestamp);
}

void test_counters_init() {
    // Retrieve time before calling function under test
    struct timeval tv;
    int ret = gettimeofday(&tv, NULL);
    if (ret != 0) {
        perror("gettimeofday");
        exit(EXIT_FAILURE);
    }
    uint64_t timestamp = ((uint64_t)tv.tv_sec) * 1000000 + ((uint64_t)tv.tv_usec);
    // Call function under test
    initial_values_t init_values = counters_init("test", "counter1");
    CU_ASSERT(init_values.is_initialized);
    CU_ASSERT_EQUAL(init_values.packets_out, 0);
    CU_ASSERT_EQUAL(init_values.packets_in, 0);
    CU_ASSERT_EQUAL(init_values.packets_both, 0);
    CU_ASSERT(init_values.microseconds > timestamp);
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
    printf("Test suite: counters\n");
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("counters", NULL, NULL);
    // Add and run tests
    CU_add_test(suite, "counter_read_packets", test_counter_read_packets);
    CU_add_test(suite, "counter_read_bytes", test_counter_read_bytes);
    CU_add_test(suite, "counter_read_microseconds", test_counter_read_microseconds);
    CU_add_test(suite, "counters_init", test_counters_init);
    CU_basic_run_tests();
    return 0;
}
