/**
 * @file src/dns_map.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Implementation of a DNS domain name to IP addresses mapping, using Joshua J Baker's hashmap.c (https://github.com/tidwall/hashmap.c)
 * @date 2022-09-06
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "dns_map.h"


/**
 * Hash function for the DNS table.
 * 
 * @param item DNS table entry to hash
 * @param seed0 first seed
 * @param seed1 second seed
 * @return hash value for the given DNS table entry
 */
static uint64_t dns_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    const dns_entry_t *entry = (dns_entry_t *) item;
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
static int dns_compare(const void *a, const void *b, void *udata) {
    const dns_entry_t *entry1 = (dns_entry_t *) a;
    const dns_entry_t *entry2 = (dns_entry_t *) b;
    return strcmp(entry1->domain_name, entry2->domain_name);
}

/**
 * Free an entry of the DNS table.
 * 
 * @param item the entry to free
 */
static void dns_free(void *item) {
    free(((dns_entry_t *) item)->ip_list.ip_addresses);
}

/**
 * @brief Checks if a dns_entry_t structure contains a given IP address.
 *
 * @param dns_entry pointer to the DNS entry to process
 * @param ip_address IP address to check the presence of
 * @return true if the IP address is present in the DNS entry, false otherwise
 */
bool dns_entry_contains(dns_entry_t *dns_entry, ip_addr_t ip_address) {
    if (dns_entry == NULL || dns_entry->ip_list.ip_addresses == NULL) {
        // DNS entry or IP address list is NULL
        return false;
    }

    // Not NULL, search for the IP address
    for (uint8_t i = 0; i < dns_entry->ip_list.ip_count; i++) {
        if (compare_ip(*(dns_entry->ip_list.ip_addresses + i), ip_address)) {
            // IP address found
            return true;
        }
    }
    // IP address not found
    return false;
}

/**
 * Create a new DNS table.
 * Uses random seeds for the hash function.
 * 
 * @return the newly created DNS table, or NULL if creation failed
 */
dns_map_t* dns_map_create() {
    return hashmap_new(
        sizeof(dns_entry_t), // Size of one entry
        DNS_MAP_INIT_SIZE,   // Hashmap initial size
        rand(),              // Optional seed 1
        rand(),              // Optional seed 2
        &dns_hash,           // Hash function
        &dns_compare,        // Compare function
        &dns_free,           // Element free function
        NULL                 // User data, unused
    );
}

/**
 * Free the memory allocated for a DNS table.
 * 
 * @param table the DNS table to free
 */
void dns_map_free(dns_map_t *table) {
    hashmap_free(table);
}

/**
 * Add IP addresses corresponding to a given domain name in the DNS table.
 * If the domain name was already present, its IP addresses will be replaced by the new ones.
 *
 * @param table the DNS table to add the entry to
 * @param domain_name the domain name of the entry
 * @param ip_list an ip_list_t structure containing the list of IP addresses
 */
void dns_map_add(dns_map_t *table, char *domain_name, ip_list_t ip_list) {
    hashmap_set(table, &(dns_entry_t){ .domain_name = domain_name, .ip_list = ip_list });
}

/**
 * Remove a domain name, and its corresponding IP addresses, from the DNS table.
 * 
 * @param table the DNS table to remove the entry from
 * @param domain_name the domain name of the entry to remove
 */
void dns_map_remove(dns_map_t *table, char *domain_name) {
    dns_entry_t *entry = hashmap_delete(table, &(dns_entry_t){ .domain_name = domain_name });
    if (entry != NULL)
        dns_free(entry);
}

/**
 * Retrieve the IP addresses corresponding to a given domain name in the DNS table.
 * 
 * @param table the DNS table to retrieve the entry from
 * @param domain_name the domain name of the entry to retrieve
 * @return a pointer to a dns_entry structure containing the IP addresses corresponding to the domain name,
 *         or NULL if the domain name was not found in the DNS table
 */
dns_entry_t* dns_map_get(dns_map_t *table, char *domain_name) {
    return (dns_entry_t *) hashmap_get(table, &(dns_entry_t){ .domain_name = domain_name });
}

/**
 * Retrieve the IP addresses corresponding to a given domain name,
 * and remove the domain name from the DNS table.
 * 
 * @param table the DNS table to retrieve the entry from
 * @param domain_name the domain name of the entry to retrieve
 * @return a pointer to a dns_entry structure containing the IP addresses corresponding to the domain name,
 *         or NULL if the domain name was not found in the DNS table
 */
dns_entry_t* dns_map_pop(dns_map_t *table, char *domain_name) {
    return (dns_entry_t *) hashmap_delete(table, &(dns_entry_t){ .domain_name = domain_name });
}
