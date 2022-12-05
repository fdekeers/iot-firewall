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
    dns_map_destroy(table);
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
    dns_map_destroy(table);
}

/**
 * Test adding and removing entries in a DNS table.
 */
void test_dns_map_add_remove() {
    dns_map_t *table = dns_map_create();

    // Add IP addresses for www.google.com
    char **google_ips = (char **) malloc(2 * sizeof(char *));
    *google_ips = "192.168.1.1";
    *(google_ips + 1) = "192.168.1.2";
    dns_map_add(table, "www.google.com", 2, google_ips);
    CU_ASSERT_EQUAL(hashmap_count(table), 1);

    // Add IP addresses for www.example.com
    char **example_ips = (char **) malloc(2 * sizeof(char *));
    *example_ips = "192.168.1.3";
    *(example_ips + 1) = "192.168.1.4";
    dns_map_add(table, "www.example.com", 2, example_ips);
    CU_ASSERT_EQUAL(hashmap_count(table), 2);

    // Remove all IP addresses
    dns_map_remove(table, "www.google.com");
    CU_ASSERT_EQUAL(hashmap_count(table), 1);
    dns_map_remove(table, "www.example.com");
    CU_ASSERT_EQUAL(hashmap_count(table), 0);
    dns_map_destroy(table);
}

/**
 * Test retrieving entries from a DNS table.
 */
void test_dns_map_get() {
    dns_map_t *table = dns_map_create();
    
    // Add IP addresses for www.google.com
    char **google_ips = (char **) malloc(2 * sizeof(char *));
    *google_ips = "192.168.1.1";
    *(google_ips + 1) = "192.168.1.2";
    dns_map_add(table, "www.google.com", 2, google_ips);
    
    // Verify getting IP addresses for www.google.com
    dns_entry_t *actual = dns_map_get(table, "www.google.com");
    CU_ASSERT_PTR_NOT_NULL(actual);
    CU_ASSERT_EQUAL(actual->ip_count, 2);
    for (int i = 0; i < actual->ip_count; i++) {
        CU_ASSERT_STRING_EQUAL(*(actual->ip_addresses + i), *(google_ips + i));
    }

    // Add IP addresses for www.example.com
    char **example_ips = (char **) malloc(2 * sizeof(char *));
    *example_ips = "192.168.1.3";
    *(example_ips + 1) = "192.168.1.4";
    dns_map_add(table, "www.example.com", 2, example_ips);

    // Verify getting IP addresses for www.example.com
    actual = dns_map_get(table, "www.example.com");
    CU_ASSERT_PTR_NOT_NULL(actual);
    CU_ASSERT_EQUAL(actual->ip_count, 2);
    for (int i = 0; i < actual->ip_count; i++) {
        CU_ASSERT_STRING_EQUAL(*(actual->ip_addresses + i), *(example_ips + i));
    }
    
    dns_map_destroy(table);
}

/**
 * Test popping entries from a DNS table.
 */
void test_dns_map_pop() {
    dns_map_t *table = dns_map_create();

    // Add IP addresses for www.google.com
    char **google_ips = (char **) malloc(2 * sizeof(char *));
    *google_ips = "192.168.1.1";
    *(google_ips + 1) = "192.168.1.2";
    dns_map_add(table, "www.google.com", 2, google_ips);

    // Add IP addresses for www.example.com
    char **example_ips = (char **) malloc(2 * sizeof(char *));
    *example_ips = "192.168.1.3";
    *(example_ips + 1) = "192.168.1.4";
    dns_map_add(table, "www.example.com", 2, example_ips);

    // Verify popping IP addresses for www.google.com
    dns_entry_t *actual = dns_map_pop(table, "www.google.com");
    CU_ASSERT_PTR_NOT_NULL(actual);
    CU_ASSERT_EQUAL(actual->ip_count, 2);
    for (int i = 0; i < actual->ip_count; i++) {
        CU_ASSERT_STRING_EQUAL(*(actual->ip_addresses + i), *(google_ips + i));
    }
    CU_ASSERT_EQUAL(hashmap_count(table), 1);
    actual = dns_map_pop(table, "www.google.com");
    CU_ASSERT_PTR_NULL(actual);

    // Verify popping IP addresses for www.example.com
    actual = dns_map_pop(table, "www.example.com");
    CU_ASSERT_PTR_NOT_NULL(actual);
    CU_ASSERT_EQUAL(actual->ip_count, 2);
    for (int i = 0; i < actual->ip_count; i++) {
        CU_ASSERT_STRING_EQUAL(*(actual->ip_addresses + i), *(example_ips + i));
    }
    CU_ASSERT_EQUAL(hashmap_count(table), 0);
    actual = dns_map_pop(table, "www.example.com");
    CU_ASSERT_PTR_NULL(actual);
    
    dns_map_destroy(table);
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
    return 0;
}
