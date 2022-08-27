#include <stdint.h>


////////// TYPE DEFINITIONS //////////

/**
 * DNS Message
 */
typedef struct dns_message {
    dns_header header;
    dns_question_list question_list;
    dns_rr_list answer_list;
    dns_rr_list authority_list;
    dns_rr_list additional_list;
} dns_message;

/**
 * DNS Header
 */
typedef struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
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
 * DNS list of Questions
 */
typedef struct dns_question_list {
    dns_question *questions;
} dns_question_list;

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
 * DNS Resource Records list
 */
typedef struct dns_rr_list {
    dns_resource_record *records;
} dns_rr_list;



////////// FUNCTIONS SIGNATURES //////////

/**
 * Parse a DNS message
 * @param length the length of the message
 * @param message the DNS message to parse
 * @return the parsed message
 */
dns_message dns_parse_message(int length, unsigned char *data);

/**
 * Parse a DNS header
 * @param header the DNS message to parse
 * @return the parsed header
 */
dns_header dns_parse_header(unsigned char *data);

/**
 * Parse a DNS question section
 * @param data the DNS message to parse
 * @return the parsed question section
 */
dns_question_list dns_parse_question(unsigned char *data);

/**
 * Parse a DNS resource record list
 * @param data the DNS message to parse
 * @return the parsed resource records list
 */
dns_rr_list dns_parse_rr_list(unsigned char *data);
