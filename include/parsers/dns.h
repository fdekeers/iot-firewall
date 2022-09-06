#ifndef _IOTFIREWALL_DNS_
#define _IOTFIREWALL_DNS_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "packet_utils.h"

#define DNS_HEADER_SIZE 12
#define DNS_DOMAIN_NAME_SIZE 100
#define DNS_COMPRESSION_MASK 0x3fff


////////// TYPE DEFINITIONS //////////

/**
 * DNS types
 */
typedef enum {
    A     =  1,
    NS    =  2,
    MD    =  3,
    MF    =  4,
    CNAME =  5,
    SOA   =  6,
    MB    =  7,
    MG    =  8,
    MR    =  9,
    NULL_ = 10,
    WKS   = 11,
    PTR   = 12,
    HINFO = 13,
    MINFO = 14,
    MX    = 15,
    TXT   = 16,
    AAAA  = 28
} dns_rr_type;

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
    dns_rr_type rtype;
    uint16_t rclass;
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

/**
 * Used to keep track of already parsed domain names.
 * Stores the domain name and its length.
 * Used for DNS name compression.
 */
typedef struct parsed_domain_name {
    uint16_t length;
    char *domain_name;
} parsed_domain_name;

/**
 * Used to keep track of current state of the parsed DNS message.
 */
typedef struct dns_parsing_state {
    uint16_t offset;
    parsed_domain_name *parsed_domain_names;
} dns_parsing_state;


////////// FUNCTIONS //////////

///// PARSE FUNCTIONS /////

/**
 * Parse a DNS header.
 * A DNS header is always 12 bytes.
 * 
 * @param data a pointer pointing to the start of the DNS message
 * @param state a pointer to the current parsing state
 * @return the parsed header
 */
dns_header dns_parse_header(unsigned char *data, dns_parsing_state *state);

/**
 * Parse a DNS question section.
 * 
 * @param qdcount the number of questions present in the question section
 * @param data a pointer pointing to the start of the DNS message
 * @param state a pointer to the current parsing state
 * @return the parsed question section
 */
dns_question* dns_parse_questions(uint16_t qdcount, unsigned char *data, dns_parsing_state *state);

/**
 * Parse a DNS resource record list.
 * 
 * @param count the number of resource records present in the section
 * @param data a pointer pointing to the start of the DNS message
 * @param state a pointer to the current parsing state
 * @return the parsed resource records list
 */
dns_resource_record* dns_parse_rrs(uint16_t count, unsigned char *data, dns_parsing_state *state);

/**
 * Parse a DNS message.
 * 
 * @param length the length of the message
 * @param data a pointer pointing to the start of the DNS message
 * @param state a pointer to the current parsing state
 * @return the parsed message
 */
dns_message dns_parse_message(size_t length, unsigned char *data);


///// PRINT FUNCTIONS /////

/**
 * Print a DNS header.
 * 
 * @param message the DNS header
 */
void dns_print_header(dns_header header);

/**
 * Print a DNS Question
 * 
 * @param question the DNS Question
 */
void dns_print_question(dns_question question);

/**
 * Print a DNS Question section.
 * 
 * @param qdcount the number of Questions in the Question section
 * @param questions the list of DNS Questions
 */
void dns_print_questions(uint16_t qdcount, dns_question *questions);

/**
 * Print a DNS Resource Record.
 * 
 * @param section_name the name of the Resource Record section
 * @param rr the DNS Resource Record
 */
void dns_print_rr(char* section_name, dns_resource_record rr);

/**
 * Print a DNS Resource Records section.
 * 
 * @param section_name the name of the Resource Record section
 * @param count the number of Resource Records in the section
 * @param rrs the list of DNS Resource Records
 */
void dns_print_rrs(char* section_name, uint16_t count, dns_resource_record *rrs);

/**
 * Print a DNS message.
 * 
 * @param message the DNS message
 */
void dns_print_message(dns_message message);

#endif /* _IOTFIREWALL_DNS_ */
