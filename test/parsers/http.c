/**
 * @file test/parsers/http.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Unit tests for the HTTP parser
 * @date 2022-20-09
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
#include "parsers/http.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


/**
 * @brief Unit test for the HTTP parser.
 */
void test_http() {

    char *hexstring = "450000ccb11f400040065845c0a801a16e2b005387b8005023882026a6ab695450180e4278860000474554202f67736c623f747665723d322669643d33363932313536313726646d3d6f74732e696f2e6d692e636f6d2674696d657374616d703d38267369676e3d6a327a743325324270624177637872786f765155467443795a3644556d47706c584e4b723169386a746552623425334420485454502f312e310d0a486f73743a20646e732e696f2e6d692e636f6d0d0a557365722d4167656e743a204d496f540d0a0d0a";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length

    size_t skipped = get_ip_header_length(payload);
    uint16_t src_port = get_src_port(payload + skipped);
    skipped += get_tcp_header_length(payload + skipped);
    http_message_t actual = http_parse_message(payload + skipped, src_port);
    http_print_message(actual);

    // Test method and header of the HTTP message
    http_message_t expected;
    expected.method = GET;
    expected.uri = "/gslb?tver=2&id=369215617&dm=ots.io.mi.com&timestamp=8&sign=j2zt3%2BpbAwcxrxovQUFtCyZ6DUmGplXNKr1i8jteRb4%3D";
    CU_ASSERT_EQUAL(actual.method, expected.method);
    CU_ASSERT_STRING_EQUAL(actual.uri, expected.uri);

}

/**
 * Driver function for the unit tests.
 */
int main(int argc, char const *argv[])
{
    // Initialize registry and suite
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("http", NULL, NULL);
    // Run tests
    CU_add_test(suite, "http", test_http);
    CU_basic_run_tests();
    return 0;
}
