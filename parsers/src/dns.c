#include "dns.h"


///// PARSE FUNCTIONS /////

/**
 * Parse a DNS message.
 * 
 * @param length the length of the message
 * @param message the DNS message to parse
 * @return the parsed message
 */
dns_message dns_parse_message(size_t length, unsigned char **data) {
    dns_message message;
    // Parse DNS header
    message.header = dns_parse_header(data);
    // If present, parse DNS Question section
    if (message.header.qdcount > 0) {
        message.questions = dns_parse_questions(message.header.qdcount, data);
    }
    // If present, parse DNS Answer section
    if (message.header.ancount > 0) {
        message.answers = dns_parse_rrs(message.header.ancount, data);
    }
    // If present, parse DNS Authority section
    if (message.header.nscount > 0) {
        message.authorities = dns_parse_rrs(message.header.nscount, data);
    }
    // If present, parse DNS Additional section
    if (message.header.arcount > 0) {
        message.additionals = dns_parse_rrs(message.header.arcount, data);
    }
    return message;
}

/**
 * Parse a DNS header.
 * 
 * A DNS header is always 12 bytes.
 * @param data a double pointer pointing to the start of the header
 * @return the parsed header
 */
dns_header dns_parse_header(unsigned char **data) {
    // Init
    uint16_t *fields = (uint16_t *) *data;
    dns_header header;

    // Parse fields
    header.id = ntohs(*fields);
    header.flags = ntohs(*(fields + 1));
    header.qdcount = ntohs(*(fields + 2));
    header.ancount = ntohs(*(fields + 3));
    header.nscount = ntohs(*(fields + 4));
    header.arcount = ntohs(*(fields + 5));

    // Update message pointer for next section
    *data += DNS_HEADER_SIZE;
    return header;
}

/**
 * Parse a DNS Domain Name.
 * 
 * @param data a double pointer pointing to the start of the domain name
 * @return the parsed domain name
 */
char* dns_parse_domain_name(unsigned char **data) {
    char* domain_name = (char*) malloc(DNS_DOMAIN_NAME_SIZE);
    do {
        uint8_t label_length = **data;
        for (int i = 1; i <= label_length; i++) {
            *(domain_name++) = **(data + i);
        }
        *(domain_name++) = '.';
        *data += label_length + 1;
    } while (**data != '\0');
    *domain_name = '\0';
    (*data)++;
    return domain_name;
}

/**
 * Parse a DNS Question section.
 * 
 * @param length the number of questions present in the question section
 * @param data a double pointer pointing to the start of the question section
 * @return the parsed question section
 */
dns_question* dns_parse_questions(size_t qdcount, unsigned char **data) {
    // Init
    printf("Here");
    dns_question *questions = (dns_question *) malloc(qdcount * sizeof(dns_question));
    // Iterate over all questions
    for (size_t i = 0; i < qdcount; i++) {
        // Parse domain name
        (questions + i)->qname = dns_parse_domain_name(data);
        // Parse type and class
        uint16_t *fields = (uint16_t *) *data;
        (questions + i)->qtype = ntohs(*fields);
        (questions + i)->qclass = ntohs(*(fields+1));
        *data += 4;
    }
    return questions;
}

/**
 * Parse a DNS Resource Record list.
 * @param length the number of resource records present in the section
 * @param data @param data a double pointer pointing to the start of the resource record section
 * @return the parsed resource records list
 */
dns_resource_record* dns_parse_rrs(size_t length, unsigned char **data) {
    return NULL;
}


///// PRINT FUNCTIONS /////

/**
 * Print a DNS header.
 * 
 * @param message the DNS header
 */
void dns_print_header(dns_header header) {
    printf("DNS Header:\n");
    printf("  ID: %#hx\n", header.id);
    printf("  Flags: %#hx\n", header.flags);
    printf("  Questions count: %hd\n", header.qdcount);
    printf("  Answers count: %hd\n", header.ancount);
    printf("  Authority name servers count: %hd\n", header.nscount);
    printf("  Additional records count: %hd\n", header.arcount);
}

/**
 * Print a DNS Question section.
 * 
 * @param questions the list of DNS Questions
 */
void dns_print_questions(dns_question *questions) {
    printf("Question section\n");
}

/**
 * Print a DNS Resource Records section.
 * 
 * @param rrs the list of DNS Resource Records
 */
void dns_print_rrs(dns_resource_record *rrs) {
    printf("RR section\n");
}

/**
 * Print a DNS message.
 * 
 * @param message the DNS message
 */
void dns_print_message(dns_message message) {
    dns_print_header(message.header);
    dns_print_questions(message.questions);
    dns_print_rrs(message.answers);
    dns_print_rrs(message.authorities);
    dns_print_rrs(message.additionals);
}
