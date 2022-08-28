#ifndef _IOTFIREWALL_DNS_
#define _IOTFIREWALL_DNS_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#define DNS_HEADER_SIZE 12
#define DNS_DOMAIN_NAME_SIZE 100


////////// TYPE DEFINITIONS //////////

/**
 * DNS Header
 */
typedef struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;  // Number of entries in Question section
    uint16_t ancount;  // Number of Resource Records in Answer section
    uint16_t nscount;  // Number of Resource Records in Authority section
    uint16_t arcount;  // Number of Resource Records in Additional section
} dns_header;

/**
 * DNS Question
 */
typedef struct dns_question {
    char *qname;
    uint16_t qtype;
    uint16_t qclass;
} dns_question;

/**
 * DNS Resource Record
 */
typedef struct dns_resource_record {
    char *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    char *rdata;
} dns_resource_record;

/**
 * DNS Message
 */
typedef struct dns_message {
    dns_header header;
    dns_question *questions;
    dns_resource_record *answers;
    dns_resource_record *authorities;
    dns_resource_record *additionals;
} dns_message;


////////// FUNCTIONS //////////

///// PARSE FUNCTIONS /////

/**
 * Parse a DNS header.
 * A DNS header is always 12 bytes.
 * 
 * @param data a double pointer pointing to the start of the header
 * @return the parsed header
 */
dns_header dns_parse_header(unsigned char **data);

/**
 * Parse a DNS question section.
 * 
 * @param qdcount the number of questions present in the question section
 * @param data a double pointer pointing to the start of the question section
 * @return the parsed question section
 */
dns_question* dns_parse_questions(size_t qdcount, unsigned char **data);

/**
 * Parse a DNS resource record list.
 * 
 * @param count the number of resource records present in the section
 * @param data @param data a double pointer pointing to the start of the resource record section
 * @return the parsed resource records list
 */
dns_resource_record* dns_parse_rrs(size_t count, unsigned char **data);

/**
 * Parse a DNS message.
 * 
 * @param length the length of the message
 * @param message a double pointer pointing to the start of the message
 * @return the parsed message
 */
dns_message dns_parse_message(size_t length, unsigned char **data);


///// PRINT FUNCTIONS /////

/**
 * Print a DNS header.
 * 
 * @param message the DNS header
 */
void dns_print_header(dns_header header);

/**
 * Print a DNS Question section.
 * 
 * @param questions the list of DNS Questions
 */
void dns_print_questions(dns_question *questions);

/**
 * Print a DNS Resource Records section.
 * 
 * @param rrs the list of DNS Resource Records
 */
void dns_print_rrs(dns_resource_record *rrs);

/**
 * Print a DNS message.
 * 
 * @param message the DNS message
 */
void dns_print_message(dns_message message);


#endif
