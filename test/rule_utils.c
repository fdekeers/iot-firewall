/**
 * @file test/rule_utils.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Unit tests for the rule utilitaries
 * @date 2022-11-02
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>
// Custom libraries
#include "rule_utils.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


/**
 * @brief Test the reading of the packets value of an nftables counter.
 */
void test_counter_read_packets() {
    CU_ASSERT_EQUAL(counter_read_packets("test-table", "counter1"), 0);
}

/**
 * @brief Test the reading of the bytes value of an nftables counter.
 */
void test_counter_read_bytes() {
    CU_ASSERT_EQUAL(counter_read_bytes("test-table", "counter1"), 0);
}

/**
 * @brief Test the reading of the current time in microseconds.
 */
void test_counter_read_microseconds() {
    // Retrieve time before calling function under test
    struct timeval tv;
    int ret = gettimeofday(&tv, NULL);
    if (ret != 0) {
        CU_FAIL("test_counter_read_microseconds: Error with gettimeofday");
        return;
    }
    uint64_t timestamp_base = ((uint64_t) tv.tv_sec) * 1000000 + ((uint64_t) tv.tv_usec);
    // Call function under test
    CU_ASSERT_TRUE(counter_read_microseconds() >= timestamp_base);
}

/**
 * @brief Test the packet counter initialization, with direction BOTH.
 */
void test_counter_packets_init_both()
{
    packet_count_t packet_count = counter_packets_init("test-table", "counter1", BOTH);
    CU_ASSERT(packet_count.is_initialized);
    CU_ASSERT_EQUAL(packet_count.packets_both, 0);
}

/**
 * @brief Test the packet counter initialization, with direction OUT.
 */
void test_counter_packets_init_out()
{
    packet_count_t packet_count = counter_packets_init("test-table", "counter1", OUT);
    CU_ASSERT(packet_count.is_initialized);
    CU_ASSERT_EQUAL(packet_count.packets_out, 0);
}

/**
 * @brief Test the packet counter initialization, with direction IN.
 */
void test_counter_packets_init_in()
{
    packet_count_t packet_count = counter_packets_init("test-table", "counter1", IN);
    CU_ASSERT(packet_count.is_initialized);
    CU_ASSERT_EQUAL(packet_count.packets_in, 0);
}

/**
 * @brief Test the duration counter initialization.
 */
void test_counter_duration_init() {
    // Retrieve time before calling function under test
    struct timeval tv;
    int ret = gettimeofday(&tv, NULL);
    if (ret != 0)
    {
        CU_FAIL("test_counters_init: Error with gettimeofday");
        return;
    }
    uint64_t timestamp = ((uint64_t)tv.tv_sec) * 1000000 + ((uint64_t)tv.tv_usec);

    // Initialize duration counter
    duration_t duration = counter_duration_init();
    CU_ASSERT(duration.is_initialized);
    CU_ASSERT(duration.microseconds >= timestamp);
}

/**
 * @brief Test the deletion of an nftables rule.
 */
void test_delete_nft_rule() {
    // Add a dummy rule
    char *rule = "ip saddr 192.168.1.1";
    uint16_t length = 41 + strlen(rule);
    char add_rule_cmd[length];
    int ret = snprintf(add_rule_cmd, length, "sudo nft add rule test-table test-chain %s", rule);
    if (ret != length - 1) {
        CU_FAIL("test_delete_nft_rule: could not build the command to add the rule.");
        return;
    }
    ret = system(add_rule_cmd);
    if (ret == -1) {
        CU_FAIL("test_delete_nft_rule: could not add the rule.");
        return;
    }
    // Delete the rule
    bool result = delete_nft_rule("test-table", "test-chain", rule);
    CU_ASSERT_TRUE(result);
}

/**
 * Test suite entry point.
 */
int main(int argc, char const *argv[]) {
    // Initialize the nftables table and counter
    system("sudo nft delete table test-table");
    system("sudo nft add table test-table");
    system("sudo nft add chain test-table test-chain { type filter hook prerouting priority 0 \\; }");
    system("sudo nft add counter test-table counter1");
    system("sudo nft add counter test-table counter1-out");
    system("sudo nft add counter test-table counter1-in");
    // Initialize the CUnit test registry and suite
    printf("Test suite: rule_utils\n");
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("rule_utils", NULL, NULL);
    // Add and run tests
    CU_add_test(suite, "counter_read_packets", test_counter_read_packets);
    CU_add_test(suite, "counter_read_bytes", test_counter_read_bytes);
    CU_add_test(suite, "counter_read_microseconds", test_counter_read_microseconds);
    CU_add_test(suite, "counter_packet_init_both", test_counter_packets_init_both);
    CU_add_test(suite, "counter_packet_init_out", test_counter_packets_init_out);
    CU_add_test(suite, "counter_packet_init_in", test_counter_packets_init_in);
    CU_add_test(suite, "counter_duration_init", test_counter_duration_init);
    CU_add_test(suite, "delete_nft_rule", test_delete_nft_rule);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}
