/**
 * @file test/packet_utils.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Unit tests for the packet utilities
 * @date 2022-09-13
 * 
 * @copyright Copyright (c) 2022
 * 
 */

// Standard libraries
#include <stdlib.h>
#include <string.h>
// Custom libraries
#include "packet_utils.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


/**
 * @brief Unit test for the function hexstr_to_payload.
 */
void test_hexstr_to_payload() {
    char *hexstr = "48656c6c6f20576f726c6421";
    uint8_t expected[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};
    uint8_t *actual;
    size_t length = hexstr_to_payload(hexstr, &actual);
    CU_ASSERT_EQUAL(length, strlen(hexstr) / 2);  // Verify payload length
    // Verify payload byte by byte
    for (uint8_t i = 0; i < length; i++) {
        CU_ASSERT_EQUAL(*(actual + i), expected[i]);
    }
}

/**
 * @brief Unit test for the function ipv4_net_to_str.
 */
void test_ipv4_net_to_str() {
    uint32_t ipv4_net = 0xa101a8c0;
    char *expected = "192.168.1.161";
    char *actual = ipv4_net_to_str(ipv4_net);
    CU_ASSERT_STRING_EQUAL(actual, expected);
}

/**
 * @brief Unit test for the function ipv4_str_to_net.
 */
void test_ipv4_str_to_net() {
    char *ipv4_str = "192.168.1.161";
    uint32_t expected = 0xa101a8c0;
    uint32_t actual = ipv4_str_to_net(ipv4_str);
    CU_ASSERT_EQUAL(actual, expected);
}

/**
 * @brief Unit test for the function ipv4_hex_to_str.
 */
void test_ipv4_hex_to_str() {
    char *ipv4_hex = "\xc0\xa8\x01\xa1";
    char *expected = "192.168.1.161";
    char *actual = ipv4_hex_to_str(ipv4_hex);
    CU_ASSERT_STRING_EQUAL(actual, expected);
}

/**
 * @brief Unit test for the function ipv4_str_to_hex.
 */
void test_ipv4_str_to_hex() {
    char *ipv4_str = "192.168.1.161";
    char *expected = "\xc0\xa8\x01\xa1";
    char *actual = ipv4_str_to_hex(ipv4_str);
    for (uint8_t i = 0; i < 4; i++) {
        CU_ASSERT_EQUAL(*(actual + i), *(expected + i))
    }
}

/**
 * Test suite entry point.
 */
int main(int argc, char const *argv[])
{
    // Initialize the CUnit test registry and suite
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("packet_utils", NULL, NULL);
    // Add and run tests
    CU_add_test(suite, "hexstr_to_payload", test_hexstr_to_payload);
    CU_add_test(suite, "ipv4_net_to_str", test_ipv4_net_to_str);
    CU_add_test(suite, "ipv4_str_to_net", test_ipv4_str_to_net);
    CU_add_test(suite, "ipv4_hex_to_str", test_ipv4_hex_to_str);
    CU_add_test(suite, "ipv4_str_to_hex", test_ipv4_str_to_hex);
    CU_basic_run_tests();
    return 0;
}
