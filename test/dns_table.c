/**
 * @file test/dns_table.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Unit tests for the DNS table
 * @date 2022-09-06
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <string.h>
// Custom libraries
#include "hashmap.h"
#include "dns_table.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

/**
 * Test the creation of a DNS table.
 */
void test_dns_table_create() {
    dns_table *table = dns_table_create();
    CU_ASSERT_PTR_NOT_NULL(table);
    CU_ASSERT_EQUAL(hashmap_count(table), 0);
    dns_table_destroy(table);
}

/**
 * Test operations on an empty DNS table.
 */
void test_dns_table_empty() {
    dns_table *table = dns_table_create();
    char *ip = dns_table_get(table, "www.google.com");
    CU_ASSERT_PTR_NULL(ip);
    ip = dns_table_pop(table, "www.google.com");
    CU_ASSERT_PTR_NULL(ip);
    dns_table_remove(table, "www.google.com");  // Does nothing, but should not crash
    dns_table_destroy(table);
}

/**
 * Test adding and removing entries in a DNS table.
 */
void test_dns_table_add_remove() {
    dns_table *table = dns_table_create();
    dns_table_add(table, "www.google.com", "192.168.1.1");
    CU_ASSERT_EQUAL(hashmap_count(table), 1);
    dns_table_add(table, "www.example.com", "192.168.1.2");
    CU_ASSERT_EQUAL(hashmap_count(table), 2);
    dns_table_remove(table, "www.google.com");
    CU_ASSERT_EQUAL(hashmap_count(table), 1);
    dns_table_remove(table, "www.example.com");
    CU_ASSERT_EQUAL(hashmap_count(table), 0);
    dns_table_destroy(table);
}

/**
 * Test retrieving entries from a DNS table.
 */
void test_dns_table_get() {
    dns_table *table = dns_table_create();
    dns_table_add(table, "www.google.com", "192.168.1.1");
    dns_table_add(table, "www.example.com", "192.168.1.2");
    char *ip = dns_table_get(table, "www.google.com");
    CU_ASSERT_STRING_EQUAL(ip, "192.168.1.1");
    ip = dns_table_get(table, "www.example.com");
    CU_ASSERT_STRING_EQUAL(ip, "192.168.1.2");
    dns_table_destroy(table);
}

/**
 * Test popping entries from a DNS table.
 */
void test_dns_table_pop() {
    dns_table *table = dns_table_create();
    dns_table_add(table, "www.google.com", "192.168.1.1");
    dns_table_add(table, "www.example.com", "192.168.1.2");
    char *ip = dns_table_pop(table, "www.google.com");
    CU_ASSERT_STRING_EQUAL(ip, "192.168.1.1");
    CU_ASSERT_EQUAL(hashmap_count(table), 1);
    ip = dns_table_pop(table, "www.google.com");
    CU_ASSERT_PTR_NULL(ip);
    ip = dns_table_pop(table, "www.example.com");
    CU_ASSERT_STRING_EQUAL(ip, "192.168.1.2");
    CU_ASSERT_EQUAL(hashmap_count(table), 0);
    ip = dns_table_pop(table, "www.example.com");
    CU_ASSERT_PTR_NULL(ip);
    dns_table_destroy(table);
}


/**
 * Test suite entry point.
 */
int main(int argc, char const *argv[])
{
    // Initialize the CUnit test registry and suite
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    CU_pSuite suite = CU_add_suite("dns_table", NULL, NULL);
    // Add and run tests
    CU_add_test(suite, "dns_table_create", test_dns_table_create);
    CU_add_test(suite, "dns_table_empty", test_dns_table_empty);
    CU_add_test(suite, "dns_table_add_remove", test_dns_table_add_remove);
    CU_add_test(suite, "dns_table_get", test_dns_table_get);
    CU_add_test(suite, "dns_table_pop", test_dns_table_pop);
    CU_basic_run_tests();
    return 0;
}
