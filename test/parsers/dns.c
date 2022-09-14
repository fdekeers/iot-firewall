/**
 * @file test/parsers/dns.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Unit tests for the DNS parser
 * @date 2022-09-09
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
#include "parsers/dns.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


/**
 * Unit test for the header section of a DNS message.
 * Verify that each header field is as expected.
 */
void compare_headers(dns_header actual, dns_header expected) {
    CU_ASSERT_EQUAL(actual.id, expected.id);
    CU_ASSERT_EQUAL(actual.flags, expected.flags);
    CU_ASSERT_EQUAL(actual.qdcount, expected.qdcount);
    CU_ASSERT_EQUAL(actual.ancount, expected.ancount);
    CU_ASSERT_EQUAL(actual.nscount, expected.nscount);
    CU_ASSERT_EQUAL(actual.arcount, expected.arcount);
}

/**
 * Unit test for the questions section
 * of a DNS message.
 */
void compare_questions(uint16_t qdcount, dns_question *actual, dns_question *expected) {
    for (int i = 0; i < qdcount; i++) {
        CU_ASSERT_STRING_EQUAL((actual + i)->qname, (expected + i)->qname);
        CU_ASSERT_EQUAL((actual + i)->qtype, (expected + i)->qtype);
        CU_ASSERT_EQUAL((actual + i)->qclass, (expected + i)->qclass);
    }
}

/**
 * Unit test for a resource records section
 * of a DNS message.
 */
void compare_rrs(uint16_t count, dns_resource_record *actual, dns_resource_record *expected) {
    for (int i = 0; i < count; i++) {
        CU_ASSERT_STRING_EQUAL((actual + i)->name, (expected + i)->name);
        CU_ASSERT_EQUAL((actual + i)->rtype, (expected + i)->rtype);
        CU_ASSERT_EQUAL((actual + i)->rclass, (expected + i)->rclass);
        CU_ASSERT_EQUAL((actual + i)->ttl, (expected + i)->ttl);
        CU_ASSERT_EQUAL((actual + i)->rdlength, (expected + i)->rdlength);
        if ((actual + i)->rdata != NULL) {
            CU_ASSERT_STRING_EQUAL((actual + i)->rdata, (expected + i)->rdata);
        }
    }
}

/**
 * Unit test for the DNS parser.
 */
void test_dns_xiaomi() {

    char *hexstring = "450000912ecc40004011879dc0a80101c0a801a10035a6b5007d76b46dca8180000100020000000008627573696e6573730b736d61727463616d6572610361706902696f026d6903636f6d0000010001c00c0005000100000258002516636e616d652d6170702d636f6d2d616d7370726f78790177066d692d64756e03636f6d00c04000010001000000930004142f61e7";
    
    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length

    size_t skipped = get_headers_length(payload);
    dns_message message = dns_parse_message(payload + skipped);
    dns_print_message(message);

    // Test different sections of the DNS message

    // Header
    dns_header expected_header;
    expected_header.id = 0x6dca;
    expected_header.flags = 0x8180;
    expected_header.qdcount = 1;
    expected_header.ancount = 2;
    expected_header.nscount = 0;
    expected_header.arcount = 0;
    compare_headers(message.header, expected_header);
    
    // Questions
    dns_question *expected_question;
    expected_question = malloc(sizeof(dns_question) * message.header.qdcount);
    expected_question->qname = "business.smartcamera.api.io.mi.com";
    expected_question->qtype = 1;
    expected_question->qclass = 1;
    compare_questions(message.header.qdcount, message.questions, expected_question);
    free(expected_question);
    
    // Answer resource records
    dns_resource_record *expected_answer;
    expected_answer = malloc(sizeof(dns_resource_record) * message.header.ancount);
    // Answer n°0
    expected_answer->name = "business.smartcamera.api.io.mi.com";
    expected_answer->rtype = 5;
    expected_answer->rclass = 1;
    expected_answer->ttl = 600;
    expected_answer->rdlength = 37;
    expected_answer->rdata = "cname-app-com-amsproxy.w.mi-dun.com";
    // Answer n°1
    (expected_answer + 1)->name = "cname-app-com-amsproxy.w.mi-dun.com";
    (expected_answer + 1)->rtype = 1;
    (expected_answer + 1)->rclass = 1;
    (expected_answer + 1)->ttl = 147;
    (expected_answer + 1)->rdlength = 4;
    (expected_answer + 1)->rdata = ipv4_str_to_hex("20.47.97.231");
    compare_rrs(message.header.ancount, message.answers, expected_answer);
    free(expected_answer);

    // Authority resource records
    dns_resource_record *expected_authority;
    expected_authority = malloc(sizeof(dns_resource_record) * message.header.nscount);
    compare_rrs(message.header.nscount, message.authorities, expected_authority);
    free(expected_authority);

    // Additional resource records
    dns_resource_record *expected_additional;
    expected_additional = malloc(sizeof(dns_resource_record) * message.header.arcount);
    compare_rrs(message.header.arcount, message.additionals, expected_additional);
    free(expected_additional);

}

/**
 * Unit test for the DNS parser.
 */
void test_dns_office() {
    char *hexstring = "4500012a4aa900003e114737826801018268e4110035d7550116a82b3ebf81800001000900000001076f75746c6f6f6b066f666669636503636f6d0000010001c00c0005000100000007000c09737562737472617465c014c03000050001000000500017076f75746c6f6f6b096f666669636533363503636f6d00c0480005000100000093001a076f75746c6f6f6b026861096f666669636533363503636f6d00c06b000500010000000b001c076f75746c6f6f6b076d732d61636463066f666669636503636f6d00c091000500010000001b000a07414d532d65667ac099c0b90001000100000004000434619ea2c0b90001000100000004000428650c62c0b9000100010000000400042863cc22c0b9000100010000000400042865791200002904d0000000000000";

    // Create payload from hexstring
    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length
    size_t skipped = get_headers_length(payload);
    dns_message message = dns_parse_message(payload + skipped);
    dns_print_message(message);

    // Test different sections of the DNS message

    // Header
    dns_header expected_header;
    expected_header.id = 0x3ebf;
    expected_header.flags = 0x8180;
    expected_header.qdcount = 1;
    expected_header.ancount = 9;
    expected_header.nscount = 0;
    expected_header.arcount = 1;
    compare_headers(message.header, expected_header);

    // Questions
    dns_question *expected_question;
    expected_question = malloc(sizeof(dns_question) * message.header.qdcount);
    expected_question->qname = "outlook.office.com";
    expected_question->qtype = 1;
    expected_question->qclass = 1;
    compare_questions(message.header.qdcount, message.questions, expected_question);
    free(expected_question);

    // Answer resource records
    dns_resource_record *expected_answer;
    expected_answer = malloc(sizeof(dns_resource_record) * message.header.ancount);
    // Answer n°0
    expected_answer->name = "outlook.office.com";
    expected_answer->rtype = 5;
    expected_answer->rclass = 1;
    expected_answer->ttl = 7;
    expected_answer->rdlength = 12;
    expected_answer->rdata = "substrate.office.com";
    // Answer n°1
    (expected_answer + 1)->name = "substrate.office.com";
    (expected_answer + 1)->rtype = 5;
    (expected_answer + 1)->rclass = 1;
    (expected_answer + 1)->ttl = 80;
    (expected_answer + 1)->rdlength = 23;
    (expected_answer + 1)->rdata = "outlook.office365.com";
    // Answer n°2
    (expected_answer + 2)->name = "outlook.office365.com";
    (expected_answer + 2)->rtype = 5;
    (expected_answer + 2)->rclass = 1;
    (expected_answer + 2)->ttl = 147;
    (expected_answer + 2)->rdlength = 26;
    (expected_answer + 2)->rdata = "outlook.ha.office365.com";
    // Answer n°3
    (expected_answer + 3)->name = "outlook.ha.office365.com";
    (expected_answer + 3)->rtype = 5;
    (expected_answer + 3)->rclass = 1;
    (expected_answer + 3)->ttl = 11;
    (expected_answer + 3)->rdlength = 28;
    (expected_answer + 3)->rdata = "outlook.ms-acdc.office.com";
    // Answer n°4
    (expected_answer + 4)->name = "outlook.ms-acdc.office.com";
    (expected_answer + 4)->rtype = CNAME;
    (expected_answer + 4)->rclass = 1;
    (expected_answer + 4)->ttl = 27;
    (expected_answer + 4)->rdlength = 10;
    (expected_answer + 4)->rdata = "AMS-efz.ms-acdc.office.com";
    // Answer n°5
    (expected_answer + 5)->name = "AMS-efz.ms-acdc.office.com";
    (expected_answer + 5)->rtype = A;
    (expected_answer + 5)->rclass = 1;
    (expected_answer + 5)->ttl = 4;
    (expected_answer + 5)->rdlength = 4;
    (expected_answer + 5)->rdata = ipv4_str_to_hex("52.97.158.162");
    // Answer n°6
    (expected_answer + 6)->name = "AMS-efz.ms-acdc.office.com";
    (expected_answer + 6)->rtype = A;
    (expected_answer + 6)->rclass = 1;
    (expected_answer + 6)->ttl = 4;
    (expected_answer + 6)->rdlength = 4;
    (expected_answer + 6)->rdata = ipv4_str_to_hex("40.101.12.98");
    // Answer n°7
    (expected_answer + 7)->name = "AMS-efz.ms-acdc.office.com";
    (expected_answer + 7)->rtype = A;
    (expected_answer + 7)->rclass = 1;
    (expected_answer + 7)->ttl = 4;
    (expected_answer + 7)->rdlength = 4;
    (expected_answer + 7)->rdata = ipv4_str_to_hex("40.99.204.34");
    // Answer n°8
    (expected_answer + 8)->name = "AMS-efz.ms-acdc.office.com";
    (expected_answer + 8)->rtype = A;
    (expected_answer + 8)->rclass = 1;
    (expected_answer + 8)->ttl = 4;
    (expected_answer + 8)->rdlength = 4;
    (expected_answer + 8)->rdata = ipv4_str_to_hex("40.101.121.18");
    // Compare and free answer
    compare_rrs(message.header.ancount, message.answers, expected_answer);
    free(expected_answer);

    // Authority resource records
    dns_resource_record *expected_authority;
    expected_authority = malloc(sizeof(dns_resource_record) * message.header.nscount);
    compare_rrs(message.header.nscount, message.authorities, expected_authority);
    free(expected_authority);

    // Additional resource records
    dns_resource_record *expected_additional;
    expected_additional = malloc(sizeof(dns_resource_record) * message.header.arcount);
    // Additional n°0
    expected_additional->name = "";
    expected_additional->rtype = OPT;
    expected_additional->rclass = 0x04d0;
    expected_additional->ttl = 0x00000000;
    expected_additional->rdlength = 0;
    expected_additional->rdata = NULL;
    // Compare and free additional
    compare_rrs(message.header.arcount, message.additionals, expected_additional);
    free(expected_additional);

}

/**
 * Main function for the unit tests.
 */
int main(int argc, char const *argv[])
{
    // Initialize registry and suite
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("dns", NULL, NULL);
    // Run tests
    CU_add_test(suite, "dns-xiaomi", test_dns_xiaomi);
    CU_add_test(suite, "dns-office", test_dns_office);
    CU_basic_run_tests();
    return 0;
}
