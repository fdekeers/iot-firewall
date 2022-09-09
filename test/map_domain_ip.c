/**
 * @file test/map_domain_ip.c
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
#include "map_domain_ip.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

/**
 * Test the creation of a DNS table.
 */
void test_map_domain_ip_create() {
    map_domain_ip *table = map_domain_ip_create();
    CU_ASSERT_PTR_NOT_NULL(table);
    CU_ASSERT_EQUAL(hashmap_count(table), 0);
    map_domain_ip_destroy(table);
    printf("test_map_domain_ip_create: OK\n");
}

/**
 * Test operations on an empty DNS table.
 */
void test_map_domain_ip_empty() {
    map_domain_ip *table = map_domain_ip_create();
    dns_entry* entry = map_domain_ip_get(table, "www.google.com");
    CU_ASSERT_PTR_NULL(entry);
    entry = map_domain_ip_pop(table, "www.google.com");
    CU_ASSERT_PTR_NULL(entry);
    map_domain_ip_remove(table, "www.google.com");  // Does nothing, but should not crash
    map_domain_ip_destroy(table);
    printf("test_map_domain_ip_empty: OK\n");
}

/**
 * Test adding and removing entries in a DNS table.
 */
void test_map_domain_ip_add_remove() {
    map_domain_ip *table = map_domain_ip_create();

    // Add IP addresses for www.google.com
    char **google_ips = (char **) malloc(2 * sizeof(char *));
    *google_ips = "192.168.1.1";
    *(google_ips + 1) = "192.168.1.2";
    map_domain_ip_add(table, "www.google.com", 2, google_ips);
    CU_ASSERT_EQUAL(hashmap_count(table), 1);

    // Add IP addresses for www.example.com
    char **example_ips = (char **) malloc(2 * sizeof(char *));
    *example_ips = "192.168.1.3";
    *(example_ips + 1) = "192.168.1.4";
    map_domain_ip_add(table, "www.example.com", 2, example_ips);
    CU_ASSERT_EQUAL(hashmap_count(table), 2);

    // Remove all IP addresses
    map_domain_ip_remove(table, "www.google.com");
    CU_ASSERT_EQUAL(hashmap_count(table), 1);
    map_domain_ip_remove(table, "www.example.com");
    CU_ASSERT_EQUAL(hashmap_count(table), 0);
    map_domain_ip_destroy(table);
    printf("test_map_domain_ip_add_remove: OK\n");
}

/**
 * Test retrieving entries from a DNS table.
 */
void test_map_domain_ip_get() {
    map_domain_ip *table = map_domain_ip_create();
    
    // Add IP addresses for www.google.com
    char **google_ips = (char **) malloc(2 * sizeof(char *));
    *google_ips = "192.168.1.1";
    *(google_ips + 1) = "192.168.1.2";
    map_domain_ip_add(table, "www.google.com", 2, google_ips);
    
    // Verify getting IP addresses for www.google.com
    dns_entry *actual = map_domain_ip_get(table, "www.google.com");
    CU_ASSERT_PTR_NOT_NULL(actual);
    CU_ASSERT_EQUAL(actual->ip_count, 2);
    for (int i = 0; i < actual->ip_count; i++) {
        CU_ASSERT_STRING_EQUAL(*(actual->ip_addresses + i), *(google_ips + i));
    }

    // Add IP addresses for www.example.com
    char **example_ips = (char **) malloc(2 * sizeof(char *));
    *example_ips = "192.168.1.3";
    *(example_ips + 1) = "192.168.1.4";
    map_domain_ip_add(table, "www.example.com", 2, example_ips);

    // Verify getting IP addresses for www.example.com
    actual = map_domain_ip_get(table, "www.example.com");
    CU_ASSERT_PTR_NOT_NULL(actual);
    CU_ASSERT_EQUAL(actual->ip_count, 2);
    for (int i = 0; i < actual->ip_count; i++) {
        CU_ASSERT_STRING_EQUAL(*(actual->ip_addresses + i), *(example_ips + i));
    }
    
    map_domain_ip_destroy(table);
    printf("test_map_domain_ip_get: OK\n");
}

/**
 * Test popping entries from a DNS table.
 */
void test_map_domain_ip_pop() {
    map_domain_ip *table = map_domain_ip_create();

    // Add IP addresses for www.google.com
    char **google_ips = (char **) malloc(2 * sizeof(char *));
    *google_ips = "192.168.1.1";
    *(google_ips + 1) = "192.168.1.2";
    map_domain_ip_add(table, "www.google.com", 2, google_ips);

    // Add IP addresses for www.example.com
    char **example_ips = (char **) malloc(2 * sizeof(char *));
    *example_ips = "192.168.1.3";
    *(example_ips + 1) = "192.168.1.4";
    map_domain_ip_add(table, "www.example.com", 2, example_ips);

    // Verify popping IP addresses for www.google.com
    dns_entry *actual = map_domain_ip_pop(table, "www.google.com");
    CU_ASSERT_PTR_NOT_NULL(actual);
    CU_ASSERT_EQUAL(actual->ip_count, 2);
    for (int i = 0; i < actual->ip_count; i++) {
        CU_ASSERT_STRING_EQUAL(*(actual->ip_addresses + i), *(google_ips + i));
    }
    CU_ASSERT_EQUAL(hashmap_count(table), 1);
    actual = map_domain_ip_pop(table, "www.google.com");
    CU_ASSERT_PTR_NULL(actual);

    // Verify popping IP addresses for www.example.com
    actual = map_domain_ip_pop(table, "www.example.com");
    CU_ASSERT_PTR_NOT_NULL(actual);
    CU_ASSERT_EQUAL(actual->ip_count, 2);
    for (int i = 0; i < actual->ip_count; i++) {
        CU_ASSERT_STRING_EQUAL(*(actual->ip_addresses + i), *(example_ips + i));
    }
    CU_ASSERT_EQUAL(hashmap_count(table), 0);
    actual = map_domain_ip_pop(table, "www.example.com");
    CU_ASSERT_PTR_NULL(actual);
    
    map_domain_ip_destroy(table);
    printf("test_map_domain_ip_pop: OK\n");
}


/**
 * Test suite entry point.
 */
int main(int argc, char const *argv[])
{
    // Initialize the CUnit test registry and suite
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("map_domain_ip", NULL, NULL);
    // Add and run tests
    CU_add_test(suite, "map_domain_ip_create", test_map_domain_ip_create);
    CU_add_test(suite, "map_domain_ip_empty", test_map_domain_ip_empty);
    CU_add_test(suite, "map_domain_ip_add_remove", test_map_domain_ip_add_remove);
    CU_add_test(suite, "map_domain_ip_get", test_map_domain_ip_get);
    CU_add_test(suite, "map_domain_ip_pop", test_map_domain_ip_pop);
    CU_basic_run_tests();
    return 0;
}
