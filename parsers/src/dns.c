#include "dns.h"


///// PARSE FUNCTIONS /////

/**
 * Parse a DNS message.
 * 
 * @param length the length of the message
 * @param message the DNS message to parse
 * @return the parsed message
 */
dns_message dns_parse_message(size_t length, unsigned char *data) {
    // Init
    dns_message message;
    dns_parsing_state *state = (dns_parsing_state *) malloc(sizeof(dns_parsing_state));  // Keep track of current parsing state
    state->offset = 0;
    state->parsed_domain_names = (char **) malloc(length);
    // Parse DNS header
    message.header = dns_parse_header(data, state);
    // If present, parse DNS Question section
    if (message.header.qdcount > 0) {
        message.questions = dns_parse_questions(message.header.qdcount, data, state);
    }
    // If present, parse DNS Answer section
    if (message.header.ancount > 0) {
        message.answers = dns_parse_rrs(message.header.ancount, data, state);
    }
    // If present, parse DNS Authority section
    if (message.header.nscount > 0) {
        message.authorities = dns_parse_rrs(message.header.nscount, data, state);
    }
    // If present, parse DNS Additional section
    if (message.header.arcount > 0) {
        message.additionals = dns_parse_rrs(message.header.arcount, data, state);
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
dns_header dns_parse_header(unsigned char *data, dns_parsing_state *state) {
    // Init
    dns_header header;

    // Parse fields
    header.id = ntohs((*((uint16_t *) (data + state->offset))));
    header.flags = ntohs((*((uint16_t *) (data + state->offset + 2))));
    header.qdcount = ntohs((*((uint16_t *) (data + state->offset + 4))));
    header.ancount = ntohs((*((uint16_t *) (data + state->offset + 6))));
    header.nscount = ntohs((*((uint16_t *) (data + state->offset + 8))));
    header.arcount = ntohs((*((uint16_t *) (data + state->offset + 10))));
    // Update offset to point after header
    state->offset += 12;

    return header;
}

/**
 * Parse a DNS Domain Name.
 * 
 * @param data a double pointer pointing to the start of the domain name
 * @return the parsed domain name
 * 
 * TODO: realloc buffer if domain name too long
 */
char* dns_parse_domain_name(unsigned char *data, dns_parsing_state *state) {
    uint16_t start = state->offset;
    char* domain_name = (char*) malloc(DNS_DOMAIN_NAME_SIZE);
    char* domain_name_ptr = domain_name;
    do {
        uint8_t length_byte = *((uint8_t *) (data + state->offset));
        if (length_byte >> 6 == 3) {  // First byte starts with 0b11
            // TODO: domain name compression
            // Offset is from start of DNS message
            //uint16_t offset = ntohs(*((uint16_t *) *data));
            return NULL;
        } else {
            // Fully written domain name
                for (int i = 1; i <= length_byte; i++) {
                    *(domain_name_ptr++) = *(data + state->offset + i);
                }
                *(domain_name_ptr++) = '.';
                state->offset += length_byte + 1;
        }
    } while (*(data + state->offset) != '\0');
    *(--domain_name_ptr) = '\0';  // Overwrite last '.' that was written
    *(state->parsed_domain_names + start) = domain_name;  // Store parsed domain name
    state->offset++;
    return domain_name;
}

/**
 * Parse a DNS Question section.
 * 
 * @param length the number of questions present in the question section
 * @param data a double pointer pointing to the start of the question section
 * @return the parsed question section
 */
dns_question* dns_parse_questions(size_t qdcount, unsigned char *data, dns_parsing_state *state) {
    // Init
    dns_question *questions = (dns_question *) malloc(qdcount * sizeof(dns_question));
    // Iterate over all questions
    for (size_t i = 0; i < qdcount; i++) {
        // Parse domain name
        (questions + i)->qname = dns_parse_domain_name(data, state);
        // Parse type and class
        (questions + i)->qtype = ntohs(*((uint16_t *) (data + state->offset)));
        (questions + i)->qclass = ntohs(*((uint16_t *) (data + state->offset + 2)));
        state->offset += 4;
    }
    return questions;
}

/**
 * Parse a DNS Resource Record list.
 * @param count the number of resource records present in the section
 * @param data a double pointer pointing to the start of the resource record section
 * @return the parsed resource records list
 */
dns_resource_record* dns_parse_rrs(size_t count, unsigned char *data, dns_parsing_state *state) {
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
    printf("DNS Question section:\n");
    printf("  Domain name: %s\n", questions->qname);
    printf("  Type: %hd\n", questions->qtype);
    printf("  Class: %hd\n", questions->qclass);
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
