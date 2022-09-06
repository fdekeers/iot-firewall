/**
 * @file src/dns_table.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Implementation of a DNS table, using Joshua J Baker's hashmap.c (https://github.com/tidwall/hashmap.c)
 * @date 2022-09-06
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "dns_table.h"


/**
 * Hash function for the DNS table.
 * 
 * @param item DNS table entry to hash
 * @param seed0 first seed
 * @param seed1 second seed
 * @return hash value for the given DNS table entry
 */
uint64_t dns_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    const dns_entry *entry = (dns_entry *) item;
    return hashmap_sip(entry->domain_name, strlen(entry->domain_name), seed0, seed1);
}

/**
 * Compare function for the DNS table.
 * 
 * @param a first DNS table entry to compare
 * @param a second DNS table entry to compare
 * @param udata user data, unused
 * @return an integer which takes the following value:
 *         - 0 if a and b are equal
 *         - less than 0 if a is smaller than b
 *         - greater than 0 if a is greater than b
 */
int dns_compare(const void *a, const void *b, void *udata) {
    const dns_entry *entry1 = (dns_entry *) a;
    const dns_entry *entry2 = (dns_entry *) b;
    return strcmp(entry1->domain_name, entry2->domain_name);
}

/**
 * Create a new DNS table.
 * Uses random seeds for the hash function.
 * 
 * @return the newly created DNS table, or NULL if creation failed
 */
dns_table* dns_table_create() {
    return hashmap_new(
        sizeof(dns_entry),    // Size of one entry
        DNS_TABLE_INIT_SIZE,  // Hashmap initial size
        rand(),               // Optional seed 1
        rand(),               // Optional seed 2
        &dns_hash,            // Hash function
        &dns_compare,         // Compare function
        NULL,                 // Element free function
        NULL                  // User data, unused
    );
}

/**
 * Destroy (free) a DNS table.
 * 
 * @param table the DNS table to destroy
 */
void dns_table_destroy(dns_table *table) {
    hashmap_free(table);
}

/**
 * Add a new entry to a DNS table.
 * 
 * @param table the DNS table to add the entry to
 * @param domain_name the domain name of the entry
 * @param ip_address the IP address corresponding to the domain name
 */
void dns_table_add(dns_table *table, char *domain_name, char *ip_address) {
    hashmap_set(table, &(dns_entry){ .domain_name = domain_name, .ip_address = ip_address });
}

/**
 * Remove an entry from a DNS table.
 * 
 * @param table the DNS table to remove the entry from
 * @param domain_name the domain name of the entry to remove
 */
void dns_table_remove(dns_table *table, char *domain_name) {
    hashmap_delete(table, &(dns_entry){ .domain_name = domain_name });
}

/**
 * Retrieve an entry from a DNS table.
 * 
 * @param table the DNS table to retrieve the entry from
 * @param domain_name the domain name of the entry to retrieve
 * @return the IP address corresponding to the domain name, or NULL if the domain name is not in the DNS table
 */
char* dns_table_get(dns_table *table, char *domain_name) {
    dns_entry *entry = hashmap_get(table, &(dns_entry){ .domain_name = domain_name });
    return entry ? entry->ip_address : NULL;
}

/**
 * Retrieve and removes an entry from a DNS table.
 * 
 * @param table the DNS table to retrieve the entry from
 * @param domain_name the domain name of the entry to retrieve
 * @return the IP address corresponding to the domain name, or NULL if the domain name is not in the DNS table
 */
char* dns_table_pop(dns_table *table, char *domain_name) {
    dns_entry *entry = hashmap_delete(table, &(dns_entry){ .domain_name = domain_name });
    return entry ? entry->ip_address : NULL;
}
