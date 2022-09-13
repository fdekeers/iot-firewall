/**
 * @file test/parsers/dhcp.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Unit tests for the DHCP parser
 * @date 2022-09-12
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
#include "parsers/dhcp.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


void set_mac_addr(char dest[], char src[]) {
    sscanf(src, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dest[0], &dest[1], &dest[2], &dest[3], &dest[4], &dest[5]);
    printf("MAC address: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]);
}

/**
 * DHCP Unit test, with a DHCP Discover message.
 */
void test_dhcp_discover() {
    char *hexstring = "4500014c00000000401179a200000000ffffffff004400430138dc40010106006617ca540000000000000000000000000000000000000000788b2ab220ea00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501013d0701788b2ab220ea3902024037070103060c0f1c2a3c0c756468637020312e32382e310c16636875616e676d695f63616d6572615f697063303139ff";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length

    skip_headers(&payload);
    dhcp_message message = dhcp_parse_message(payload);
    dhcp_print_message(message);

    // Test different sections of the DHCP message

    // Header
    /*
    dhcp_message expected;
    expected.op = BOOTREQUEST;
    expected.htype = 1;
    expected.hlen = 6;
    expected.hops = 0;
    expected.xid = 0x6617ca54;
    expected.secs = 0;
    expected.flags = 0x0000;
    expected.ciaddr = "0.0.0.0";
    expected.yiaddr = "0.0.0.0";
    expected.siaddr = "0.0.0.0";
    expected.giaddr = "0.0.0.0";
    set_mac_addr(expected.chaddr, "78:8b:2a:b2:20:ea");
    printf("MAC address: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", expected.chaddr);
    */

}

/**
 * DHCP Unit test, with a DHCP Offer message.
 */
void test_dhcp_offer() {
    char *hexstring = "45c0014820a000004011d452c0a80101c0a801a10043004401341617020106006617ca540000000000000000c0a801a1c0a8010100000000788b2ab220ea00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501023604c0a8010133040000a8c03a04000054603b04000093a80104ffffff001c04c0a801ff0304c0a801010604c0a801010f036c616eff000000";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length

    skip_headers(&payload);
    dhcp_message message = dhcp_parse_message(payload);
    dhcp_print_message(message);
}

/**
 * Main function for the unit tests.
 */
int main(int argc, char const *argv[])
{
    // Initialize registry and suite
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("dhcp", NULL, NULL);
    // Run tests
    CU_add_test(suite, "dhcp-discover", test_dhcp_discover);
    CU_add_test(suite, "dhcp-offer", test_dhcp_offer);
    CU_basic_run_tests();
    return 0;
}