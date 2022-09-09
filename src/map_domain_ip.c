/**
 * @file src/map_domain_ip.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Implementation of a DNS domain name to IP addresses mapping, using Joshua J Baker's hashmap.c (https://github.com/tidwall/hashmap.c)
 * @date 2022-09-06
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "map_domain_ip.h"


/**
 * Hash function for the DNS table.
 * 
 * @param item DNS table entry to hash
 * @param seed0 first seed
 * @param seed1 second seed
 * @return hash value for the given DNS table entry
 */
static uint64_t dns_hash(const void *item, uint64_t seed0, uint64_t seed1) {
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
static int dns_compare(const void *a, const void *b, void *udata) {
    const dns_entry *entry1 = (dns_entry *) a;
    const dns_entry *entry2 = (dns_entry *) b;
    return strcmp(entry1->domain_name, entry2->domain_name);
}

/**
 * Free an entry of the DNS table.
 * 
 * @param item the entry to free
 */
static void dns_free(void *item) {
    free(((dns_entry *) item)->ip_addresses);
}

/**
 * Create a new DNS table.
 * Uses random seeds for the hash function.
 * 
 * @return the newly created DNS table, or NULL if creation failed
 */
map_domain_ip* map_domain_ip_create() {
    return hashmap_new(
        sizeof(dns_entry),    // Size of one entry
        MAP_DOMAIN_IP_INIT_SIZE,  // Hashmap initial size
        rand(),               // Optional seed 1
        rand(),               // Optional seed 2
        &dns_hash,            // Hash function
        &dns_compare,         // Compare function
        &dns_free,            // Element free function
        NULL                  // User data, unused
    );
}

/**
 * Destroy (free) a DNS table.
 * 
 * @param table the DNS table to destroy
 */
void map_domain_ip_destroy(map_domain_ip *table) {
    hashmap_free(table);
}

/**
 * Add IP addresses corresponding to a given domain name in the DNS table.
 * If the domain name was already present, its IP addresses will be replaced by the new ones.
 * 
 * @param table the DNS table to add the entry to
 * @param domain_name the domain name of the entry
 * @param ip_count the number of IP addresses to add
 * @param ip_addresses a pointer to the IP addresses corresponding to the domain name
 */
void map_domain_ip_add(map_domain_ip *table, char *domain_name, uint16_t ip_count, char **ip_addresses) {
    hashmap_set(table, &(dns_entry){ .domain_name = domain_name, .ip_count = ip_count, .ip_addresses = ip_addresses });
}

/**
 * Remove a domain name, and its corresponding IP addresses, from the DNS table.
 * 
 * @param table the DNS table to remove the entry from
 * @param domain_name the domain name of the entry to remove
 */
void map_domain_ip_remove(map_domain_ip *table, char *domain_name) {
    dns_entry *entry = hashmap_delete(table, &(dns_entry){ .domain_name = domain_name });
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
dns_entry* map_domain_ip_get(map_domain_ip *table, char *domain_name) {
    return (dns_entry *) hashmap_get(table, &(dns_entry){ .domain_name = domain_name });
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
dns_entry* map_domain_ip_pop(map_domain_ip *table, char *domain_name) {
    return (dns_entry *) hashmap_delete(table, &(dns_entry){ .domain_name = domain_name });
}
