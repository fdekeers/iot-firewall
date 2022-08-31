#include "dns.h"

///// PARSE FUNCTIONS /////

/**
 * Parse a DNS message.
 * 
 * @param length the length of the message
 * @param data a pointer pointing to the start of the DNS message
 * @return the parsed message
 */
dns_message dns_parse_message(size_t length, unsigned char *data) {
    // Init
    dns_message message;
    dns_parsing_state *state = (dns_parsing_state *) malloc(sizeof(dns_parsing_state));  // Keep track of current parsing state
    state->offset = 0;
    state->parsed_domain_names = (parsed_domain_name *) malloc(sizeof(parsed_domain_name) * length);
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
 * @param data a pointer pointing to the start of the DNS message
 * @param state a pointer to the current parsing state
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
 * @param data a pointer pointing to the start of the DNS message
 * @param state a pointer to the current parsing state
 * @return the parsed domain name
 * 
 * TODO: realloc buffer if domain name too long
 */
char* dns_parse_domain_name(unsigned char *data, dns_parsing_state *state) {
    uint16_t start = state->offset;
    uint16_t domain_name_length = 0;
    char* domain_name = (char*) malloc(DNS_DOMAIN_NAME_SIZE);
    char* domain_name_ptr = domain_name;
    do {
        uint8_t length_byte = *((uint8_t *) (data + state->offset));
        if (length_byte >> 6 == 3) {  // First byte starts with 0b11
            // Compressed domain name, retrieve already parsed name with offset
            uint16_t offset = ntohs(*((uint16_t *) (data + state->offset))) & DNS_COMPRESSION_MASK;
            parsed_domain_name* base_domain_name = state->parsed_domain_names + offset;
            memcpy(domain_name_ptr, base_domain_name->domain_name, base_domain_name->length);
            state->offset += 2;
            return domain_name;
        } else {
            // Fully written domain name, parse it
                for (int i = 1; i <= length_byte; i++) {
                    *(domain_name_ptr++) = *(data + state->offset + i);
                }
                *(domain_name_ptr++) = '.';
                domain_name_length += length_byte + 1;
                state->offset += length_byte + 1;
        }
    } while (*(data + state->offset) != '\0');
    *(--domain_name_ptr) = '\0';  // Overwrite last '.' that was written
    // Store parsed domain name
    (state->parsed_domain_names + start)->length = domain_name_length;
    (state->parsed_domain_names + start)->domain_name = domain_name;
    state->offset++;
    return domain_name;
}

/**
 * Parse a DNS Question section.
 * 
 * @param length the number of questions present in the question section
 * @param data a pointer pointing to the start of the DNS message
 * @param state a pointer to the current parsing state
 * @return the parsed question section
 */
dns_question* dns_parse_questions(uint16_t qdcount, unsigned char *data, dns_parsing_state *state) {
    // Init
    dns_question *questions = (dns_question *) malloc(qdcount * sizeof(dns_question));
    // Iterate over all questions
    for (uint16_t i = 0; i < qdcount; i++) {
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
 * Parse a DNS Resource Record RDATA field.
 * 
 * @param rdlength the length, in bytes, of the RDATA field
 * @param data a pointer pointing to the start of the DNS message
 * @param state a pointer to the current parsing state
 * @return the parsed RDATA field
 */
char* dns_parse_rdata(uint16_t type, uint16_t rdlength, unsigned char *data, dns_parsing_state *state) {
    char *rdata;
    switch (type) {
        case CNAME:
            rdata = dns_parse_domain_name(data, state);
            break;
        default:
            rdata = (char *) malloc(sizeof(char) * rdlength);
            memcpy(rdata, data + state->offset, rdlength);
            state->offset += rdlength;
    }
    return rdata;
}


/**
 * Parse a DNS Resource Record list.
 * @param count the number of resource records present in the section
 * @param data a pointer pointing to the start of the DNS message
 * @param state a pointer to the current parsing state
 * @return the parsed resource records list
 */
dns_resource_record* dns_parse_rrs(uint16_t count, unsigned char *data, dns_parsing_state *state) {
    dns_resource_record *rrs = (dns_resource_record *) malloc(count * sizeof(dns_resource_record));
    for (uint16_t i = 0; i < count; i++) {
        // Parse domain name
        (rrs + i)->name = dns_parse_domain_name(data, state);
        // Parse type, class and TTL
        uint16_t type = ntohs(*((uint16_t *) (data + state->offset)));
        (rrs + i)->type = type;
        (rrs + i)->class = ntohs(*((uint16_t *) (data + state->offset + 2)));
        (rrs + i)->ttl = ntohl(*((uint32_t *) (data + state->offset + 4)));
        // Parse rdata
        uint16_t rdlength = ntohs(*((uint16_t *) (data + state->offset + 8)));
        (rrs + i)->rdlength = rdlength;
        state->offset += 10;
        (rrs + i)->rdata = dns_parse_rdata(type, rdlength, data, state);
    }
    return rrs;
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
void dns_print_questions(uint16_t qdcount, dns_question *questions) {
    printf("DNS Question section:\n");
    for (uint16_t i = 0; i < qdcount; i++) {
        printf("  Question n°%hd:\n", i);
        printf("    Domain name: %s\n", (questions + i)->qname);
        printf("    Type: %hd\n", (questions + i)->qtype);
        printf("    Class: %hd\n", (questions + i)->qclass);
    }
}

/**
 * Print a DNS Resource Records section.
 * 
 * @param rrs the list of DNS Resource Records
 */
void dns_print_rrs(char* section_name, uint16_t count, dns_resource_record *rrs) {
    printf("%s RRs:\n", section_name);
    for (uint16_t i = 0; i < count; i++) {
        printf("  %s RR n°%hd:\n", section_name, i);
        printf("    Name: %s\n", (rrs + i)->name);
        printf("    Type: %hd\n", (rrs + i)->type);
        printf("    Class: %hd\n", (rrs + i)->class);
        printf("    TTL [s]: %d\n", (rrs + i)->ttl);
        printf("    Data length: %hd\n", (rrs + i)->rdlength);
        printf("    RDATA: %s\n", (rrs + i)->rdata);
    }
}

/**
 * Print a DNS message.
 * 
 * @param message the DNS message
 */
void dns_print_message(dns_message message) {
    dns_print_header(message.header);
    dns_print_questions(message.header.qdcount, message.questions);
    dns_print_rrs("Answer", message.header.ancount, message.answers);
    dns_print_rrs("Authority", message.header.nscount, message.authorities);
    dns_print_rrs("Additional", message.header.arcount, message.additionals);
}
