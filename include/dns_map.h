/**
 * @file include/dns_map.h
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Implementation of a DNS domain name to IP addresses mapping, using Joshua J Baker's hashmap.c (https://github.com/tidwall/hashmap.c)
 * @date 2022-09-06
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _IOTFIREWALL_dns_map_
#define _IOTFIREWALL_dns_map_

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "hashmap.h"

// Initial size of the DNS table
// If set to 0, the default size will be 16
#define dns_map_INIT_SIZE 0


////////// TYPE DEFINITIONS //////////

/**
 * DNS table entry:
 * mapping between domain name and IP address.
 */
typedef struct dns_entry {
    char *domain_name;    // Domain name
    uint16_t ip_count;    // Number of IP addresses
    char **ip_addresses;  // List of IP addresses corresponding to the domain name
} dns_entry_t;

/**
 * Alias for the hashmap structure.
 */
typedef struct hashmap dns_map_t;


////////// FUNCTIONS //////////

/**
 * Create a new DNS table.
 * 
 * @return the newly created DNS table 
 */
dns_map_t* dns_map_create();

/**
 * Destroy (free) a DNS table.
 * 
 * @param table the DNS table to destroy
 */
void dns_map_destroy(dns_map_t *table);

/**
 * Add IP addresses corresponding to a given domain name in the DNS table.
 * If the domain name was already present, its IP addresses will be replaced by the new ones.
 * 
 * @param table the DNS table to add the entry to
 * @param domain_name the domain name of the entry
 * @param ip_count the number of IP addresses to add
 * @param ip_addresses a pointer to the IP addresses corresponding to the domain name
 */
void dns_map_add(dns_map_t *table, char *domain_name, uint16_t ip_count, char **ip_addresses);

/**
 * Remove a domain name (and its corresponding IP addresses) from the DNS table.
 * 
 * @param table the DNS table to remove the entry from
 * @param domain_name the domain name of the entry to remove
 */
void dns_map_remove(dns_map_t *table, char *domain_name);

/**
 * Retrieve the IP addresses corresponding to a given domain name in the DNS table.
 * 
 * @param table the DNS table to retrieve the entry from
 * @param domain_name the domain name of the entry to retrieve
 * @return a pointer to a dns_entry structure containing the IP addresses corresponding to the domain name,
 *         or NULL if the domain name was not found in the DNS table
 */
dns_entry_t* dns_map_get(dns_map_t *table, char *domain_name);

/**
 * Retrieve the IP addresses corresponding to a given domain name,
 * and remove the domain name from the DNS table.
 * 
 * @param table the DNS table to retrieve the entry from
 * @param domain_name the domain name of the entry to retrieve
 * @return a pointer to a dns_entry structure containing the IP addresses corresponding to the domain name,
 *         or NULL if the domain name was not found in the DNS table
 */
dns_entry_t* dns_map_pop(dns_map_t *table, char *domain_name);


#endif /* _IOTFIREWALL_dns_map_ */
