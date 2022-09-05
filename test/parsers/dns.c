#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// Custom libraries
#include "packet-utils.h"
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
        CU_ASSERT_EQUAL((actual + i)->type, (expected + i)->type);
        CU_ASSERT_EQUAL((actual + i)->class, (expected + i)->class);
        CU_ASSERT_EQUAL((actual + i)->ttl, (expected + i)->ttl);
        CU_ASSERT_EQUAL((actual + i)->rdlength, (expected + i)->rdlength);
        CU_ASSERT_STRING_EQUAL((actual + i)->rdata, (expected + i)->rdata);
    }
}

/**
 * Parse a DNS message.
 * 
 * @return the parsed DNS message
 */
void test_dns() {

    char *hexstring = "450000912ecc40004011879dc0a80101c0a801a10035a6b5007d76b46dca8180000100020000000008627573696e6573730b736d61727463616d6572610361706902696f026d6903636f6d0000010001c00c0005000100000258002516636e616d652d6170702d636f6d2d616d7370726f78790177066d692d64756e03636f6d00c04000010001000000930004142f61e7";
    
    unsigned char *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length

    payload = skip_headers(payload);
    dns_message message = dns_parse_message(length, payload);
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
    expected_answer->type = 5;
    expected_answer->class = 1;
    expected_answer->ttl = 600;
    expected_answer->rdlength = 37;
    expected_answer->rdata = "cname-app-com-amsproxy.w.mi-dun.com";
    // Answer n°1
    (expected_answer + 1)->name = "cname-app-com-amsproxy.w.mi-dun.com";
    (expected_answer + 1)->type = 1;
    (expected_answer + 1)->class = 1;
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
 * Main function for the unit tests.
 */
int main(int argc, char const *argv[])
{
    // Initialize registry and suite
    CU_initialize_registry();
    CU_pSuite suite = CU_add_suite("dns", NULL, NULL);
    // Run tests
    CU_add_test(suite, "dns", test_dns);
    CU_basic_run_tests();
    return 0;
}
