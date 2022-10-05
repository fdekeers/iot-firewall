/**
 * @file test/parsers/igmp.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Unit tests for the IGMP parser
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// Custom libraries
#include "packet_utils.h"
#include "parsers/header.h"
#include "parsers/igmp.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


/**
 * @brief Compare two IGMP messages.
 * 
 * @param actual actual IGMP message
 * @param expected expected IGMP message
 */
void compare_igmp_messages(igmp_message_t actual, igmp_message_t expected) {
    CU_ASSERT_EQUAL(actual.type, expected.type);
    CU_ASSERT_EQUAL(actual.max_resp_time, expected.max_resp_time);
    CU_ASSERT_EQUAL(actual.checksum, expected.checksum);
    CU_ASSERT_EQUAL(actual.group_address, expected.group_address);
}


/**
 * @brief Unit test with an IGMPv2 Membership Report message.
 */
void test_igmp_v2_membership_report() {

    char *hexstring = "46c000200000400001024096c0a801dee00000fb9404000016000904e00000fb";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length

    size_t skipped = get_headers_length(payload);
    igmp_message_t actual = igmp_parse_message(payload + skipped);
    igmp_print_message(actual);

    // Expected message
    igmp_message_t expected;
    expected.type = V2_MEMBERSHIP_REPORT;
    expected.max_resp_time = 0;
    expected.checksum = 0x0904;
    expected.group_address = ipv4_str_to_net("224.0.0.251");

    // Compare messages
    compare_igmp_messages(actual, expected);

}

/**
 * @brief Unit test with an IGMP Leave Group message.
 */
void test_igmp_leave_group() {

    char *hexstring = "46c00020000040000102418fc0a801dee00000029404000017000804e00000fb";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length

    size_t skipped = get_headers_length(payload);
    igmp_message_t actual = igmp_parse_message(payload + skipped);
    igmp_print_message(actual);

    // Expected message
    igmp_message_t expected;
    expected.type = LEAVE_GROUP;
    expected.max_resp_time = 0;
    expected.checksum = 0x0804;
    expected.group_address = ipv4_str_to_net("224.0.0.251");

    // Compare messages
    compare_igmp_messages(actual, expected);

}

/**
 * Main function for the unit tests.
 */
int main(int argc, char const *argv[])
{
    // Initialize registry and suite
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("igmp", NULL, NULL);
    // Run tests
    CU_add_test(suite, "igmp-v2-membership-report", test_igmp_v2_membership_report);
    CU_add_test(suite, "igmp-leave-group", test_igmp_leave_group);
    CU_basic_run_tests();
    return 0;
}
