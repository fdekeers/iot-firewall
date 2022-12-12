/**
 * @file test/dns_map.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Unit tests for the mapping structure from DNS domain names to IP addresses
 * @date 2022-09-06
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <string.h>
// Custom libraries
#include "hashmap.h"
#include "packet_utils.h"
#include "dns_map.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

/**
 * Test the creation of a DNS table.
 */
void test_dns_map_create() {
    dns_map_t *table = dns_map_create();
    CU_ASSERT_PTR_NOT_NULL(table);
    CU_ASSERT_EQUAL(hashmap_count(table), 0);
    dns_map_free(table);
}

/**
 * Test operations on an empty DNS table.
 */
void test_dns_map_empty() {
    dns_map_t *table = dns_map_create();
    dns_entry_t* entry = dns_map_get(table, "www.google.com");
    CU_ASSERT_PTR_NULL(entry);
    entry = dns_map_pop(table, "www.google.com");
    CU_ASSERT_PTR_NULL(entry);
    dns_map_remove(table, "www.google.com");  // Does nothing, but should not crash
    dns_map_free(table);
}

/**
 * Test adding and removing entries in a DNS table.
 */
void test_dns_map_add_remove() {
    dns_map_t *table = dns_map_create();

    // Add IP addresses for www.google.com
    ip_addr_t *google_ips = (ip_addr_t *) malloc(2 * sizeof(ip_addr_t));
    *google_ips = (ip_addr_t) {.version = 4, .value.ipv4 = ipv4_str_to_net("192.168.1.1")};
    *(google_ips + 1) = (ip_addr_t) {.version = 4, .value.ipv4 = ipv4_str_to_net("192.168.1.2")};
    ip_list_t ip_list_google = { .ip_count = 2, .ip_addresses = google_ips };
    dns_map_add(table, "www.google.com", ip_list_google);
    CU_ASSERT_EQUAL(hashmap_count(table), 1);

    // Add IP addresses for www.example.com
    ip_addr_t *example_ips = (ip_addr_t *)malloc(2 * sizeof(ip_addr_t));
    *example_ips = (ip_addr_t) {.version = 4, .value.ipv4 = ipv4_str_to_net("192.168.1.3")};
    *(example_ips + 1) = (ip_addr_t) {.version = 4, .value.ipv4 = ipv4_str_to_net("192.168.1.4")};
    ip_list_t ip_list_example = {.ip_count = 2, .ip_addresses = example_ips};
    dns_map_add(table, "www.example.com", ip_list_example);
    CU_ASSERT_EQUAL(hashmap_count(table), 2);

    // Remove all IP addresses
    dns_map_remove(table, "www.google.com");
    CU_ASSERT_EQUAL(hashmap_count(table), 1);
    dns_map_remove(table, "www.example.com");
    CU_ASSERT_EQUAL(hashmap_count(table), 0);
    dns_map_free(table);
}

/**
 * Test retrieving entries from a DNS table.
 */
void test_dns_map_get() {
    dns_map_t *table = dns_map_create();
    
    // Add IP addresses for www.google.com
    ip_addr_t *google_ips = (ip_addr_t *)malloc(2 * sizeof(ip_addr_t));
    *google_ips = (ip_addr_t){.version = 4, .value.ipv4 = ipv4_str_to_net("192.168.1.1")};
    *(google_ips + 1) = (ip_addr_t){.version = 4, .value.ipv4 = ipv4_str_to_net("192.168.1.2")};
    ip_list_t ip_list_google = {.ip_count = 2, .ip_addresses = google_ips};
    dns_map_add(table, "www.google.com", ip_list_google);

    // Verify getting IP addresses for www.google.com
    dns_entry_t *actual = dns_map_get(table, "www.google.com");
    CU_ASSERT_PTR_NOT_NULL(actual);
    CU_ASSERT_EQUAL(actual->ip_list.ip_count, 2);
    for (int i = 0; i < actual->ip_list.ip_count; i++) {
        CU_ASSERT_TRUE(compare_ip(*(actual->ip_list.ip_addresses + i), *(google_ips + i)));
    }

    // Add IP addresses for www.example.com
    ip_addr_t *example_ips = (ip_addr_t *)malloc(2 * sizeof(ip_addr_t));
    *example_ips = (ip_addr_t){.version = 4, .value.ipv4 = ipv4_str_to_net("192.168.1.3")};
    *(example_ips + 1) = (ip_addr_t){.version = 4, .value.ipv4 = ipv4_str_to_net("192.168.1.4")};
    ip_list_t ip_list_example = {.ip_count = 2, .ip_addresses = example_ips};
    dns_map_add(table, "www.example.com", ip_list_example);

    // Verify getting IP addresses for www.example.com
    actual = dns_map_get(table, "www.example.com");
    CU_ASSERT_PTR_NOT_NULL(actual);
    CU_ASSERT_EQUAL(actual->ip_list.ip_count, 2);
    for (int i = 0; i < actual->ip_list.ip_count; i++) {
        CU_ASSERT_TRUE(compare_ip(*(actual->ip_list.ip_addresses + i), *(example_ips + i)));
    }

    dns_map_free(table);
}

/**
 * Test popping entries from a DNS table.
 */
void test_dns_map_pop() {
    dns_map_t *table = dns_map_create();

    // Add IP addresses for www.google.com
    ip_addr_t *google_ips = (ip_addr_t *)malloc(2 * sizeof(ip_addr_t));
    *google_ips = (ip_addr_t){.version = 4, .value.ipv4 = ipv4_str_to_net("192.168.1.1")};
    *(google_ips + 1) = (ip_addr_t){.version = 4, .value.ipv4 = ipv4_str_to_net("192.168.1.2")};
    ip_list_t ip_list_google = {.ip_count = 2, .ip_addresses = google_ips};
    dns_map_add(table, "www.google.com", ip_list_google);

    // Add IP addresses for www.example.com
    ip_addr_t *example_ips = (ip_addr_t *)malloc(2 * sizeof(ip_addr_t));
    *example_ips = (ip_addr_t){.version = 4, .value.ipv4 = ipv4_str_to_net("192.168.1.3")};
    *(example_ips + 1) = (ip_addr_t){.version = 4, .value.ipv4 = ipv4_str_to_net("192.168.1.4")};
    ip_list_t ip_list_example = {.ip_count = 2, .ip_addresses = example_ips};
    dns_map_add(table, "www.example.com", ip_list_example);

    // Verify popping IP addresses for www.google.com
    dns_entry_t *actual = dns_map_pop(table, "www.google.com");
    CU_ASSERT_PTR_NOT_NULL(actual);
    CU_ASSERT_EQUAL(actual->ip_list.ip_count, 2);
    for (int i = 0; i < actual->ip_list.ip_count; i++)
    {
        CU_ASSERT_TRUE(compare_ip(*(actual->ip_list.ip_addresses + i), *(google_ips + i)));
    }
    free(actual->ip_list.ip_addresses);
    CU_ASSERT_EQUAL(hashmap_count(table), 1);
    actual = dns_map_pop(table, "www.google.com");
    CU_ASSERT_PTR_NULL(actual);

    // Verify popping IP addresses for www.example.com
    actual = dns_map_pop(table, "www.example.com");
    CU_ASSERT_PTR_NOT_NULL(actual);
    CU_ASSERT_EQUAL(actual->ip_list.ip_count, 2);
    for (int i = 0; i < actual->ip_list.ip_count; i++)
    {
        CU_ASSERT_TRUE(compare_ip(*(actual->ip_list.ip_addresses + i), *(example_ips + i)));
    }
    free(actual->ip_list.ip_addresses);
    CU_ASSERT_EQUAL(hashmap_count(table), 0);
    actual = dns_map_pop(table, "www.example.com");
    CU_ASSERT_PTR_NULL(actual);
    
    dns_map_free(table);
}


/**
 * Test suite entry point.
 */
int main(int argc, char const *argv[])
{
    // Initialize the CUnit test registry and suite
    printf("Test suite: dns_map\n");
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("dns_map", NULL, NULL);
    // Add and run tests
    CU_add_test(suite, "dns_map_create", test_dns_map_create);
    CU_add_test(suite, "dns_map_empty", test_dns_map_empty);
    CU_add_test(suite, "dns_map_add_remove", test_dns_map_add_remove);
    CU_add_test(suite, "dns_map_get", test_dns_map_get);
    CU_add_test(suite, "dns_map_pop", test_dns_map_pop);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}
