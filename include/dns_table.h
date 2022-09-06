/**
 * @file include/dns_table.h
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Implementation of a DNS table, using Joshua J Baker's hashmap.c (https://github.com/tidwall/hashmap.c)
 * @date 2022-09-06
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _IOTFIREWALL_DNS_TABLE_
#define _IOTFIREWALL_DNS_TABLE_

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "hashmap.h"

// Initial size of the DNS table
// If set to 0, the default size will be 16
#define DNS_TABLE_INIT_SIZE 0


////////// TYPE DEFINITIONS //////////

/**
 * DNS table entry:
 * mapping between domain name and IP address.
 */
typedef struct dns_entry {
    char *domain_name;
    char *ip_address;
} dns_entry;

/**
 * Alias for the hashmap structure.
 */
typedef struct hashmap dns_table;


////////// FUNCTIONS //////////

/**
 * Create a new DNS table.
 * 
 * @return the newly created DNS table 
 */
dns_table* dns_table_create();

/**
 * Destroy (free) a DNS table.
 * 
 * @param table the DNS table to destroy
 */
void dns_table_destroy(dns_table *table);

/**
 * Add a new entry to a DNS table.
 * 
 * @param table the DNS table to add the entry to
 * @param domain_name the domain name of the entry
 * @param ip_address the IP address corresponding to the domain name
 */
void dns_table_add(dns_table *table, char *domain_name, char *ip_address);

/**
 * Remove an entry from a DNS table.
 * 
 * @param table the DNS table to remove the entry from
 * @param domain_name the domain name of the entry to remove
 */
void dns_table_remove(dns_table *table, char *domain_name);

/**
 * Retrieve an entry from a DNS table.
 * 
 * @param table the DNS table to retrieve the entry from
 * @param domain_name the domain name of the entry to retrieve
 * @return the IP address corresponding to the domain name, or NULL if the domain name is not in the DNS table
 */
char* dns_table_get(dns_table *table, char *domain_name);

/**
 * Retrieve and removes an entry from a DNS table.
 * 
 * @param table the DNS table to retrieve the entry from
 * @param domain_name the domain name of the entry to retrieve
 * @return the IP address corresponding to the domain name, or NULL if the domain name is not in the DNS table
 */
char* dns_table_pop(dns_table *table, char *domain_name);


#endif /* _IOTFIREWALL_DNS_TABLE_ */
