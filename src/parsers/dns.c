/**
 * @file src/parsers/dns.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief DNS message parser
 * @date 2022-09-09
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "dns.h"


///// PARSING /////

/**
 * Parse a DNS header.
 * A DNS header is always 12 bytes.
 * 
 * @param data a pointer pointing to the start of the DNS message
 * @param offset a pointer to the current parsing offset
 * @return the parsed header
 */
dns_header_t dns_parse_header(uint8_t *data, uint16_t *offset) {
    // Init
    dns_header_t header;
    // Parse fields
    header.id = ntohs(*((uint16_t *) (data + *offset)));
    header.flags = ntohs(*((uint16_t *) (data + *offset + 2)));
    header.qr = (header.flags & DNS_QR_FLAG_MASK);
    header.qdcount = ntohs(*((uint16_t *) (data + *offset + 4)));
    header.ancount = ntohs(*((uint16_t *) (data + *offset + 6)));
    header.nscount = ntohs(*((uint16_t *) (data + *offset + 8)));
    header.arcount = ntohs(*((uint16_t *) (data + *offset + 10)));
    // Update offset to point after header
    *offset += DNS_HEADER_SIZE;

    return header;
}

/**
 * Parse a DNS Domain Name.
 * 
 * @param data a pointer pointing to the start of the DNS message
 * @param offset a pointer to the current parsing offset
 * @return the parsed domain name
 */
static char* dns_parse_domain_name(uint8_t *data, uint16_t *offset) {
    if (*(data + *offset) == '\0') {
        // Domain name is ROOT
        (*offset)++;
        return "";
    }
    uint16_t current_length = 0;
    uint16_t max_length = DNS_MAX_DOMAIN_NAME_LENGTH;
    char* domain_name = (char *) malloc(sizeof(char) * max_length);
    bool compression = false;
    uint16_t domain_name_offset = *offset;  // Other offset, might be useful for domain name compression
    while (*(data + domain_name_offset) != '\0') {
        uint8_t length_byte = *((uint8_t *) (data + domain_name_offset));
        if (length_byte >> 6 == 3) {  // Length byte starts with 0b11
            // Domain name compression
            // Advance offset by 2 bytes, and do not update it again
            if(!compression) {
                *offset += 2;
            }
            compression = true;
            // Retrieve new offset to parse domain name from
            domain_name_offset = ntohs(*((uint16_t *) (data + domain_name_offset))) & DNS_COMPRESSION_MASK;
        } else {
            // Fully written label, parse it
            for (int i = 1; i <= length_byte; i++) {
                if (current_length == max_length) {
                    // Realloc buffer
                    max_length *= 2;
                    domain_name = (char *) realloc(domain_name, sizeof(char) * max_length);
                }
                char c = *(data + domain_name_offset + i);
                *(domain_name + (current_length++)) = c;
            }
            *(domain_name + (current_length++)) = '.';
            domain_name_offset += length_byte + 1;
            if (!compression) {
                *offset = domain_name_offset;
            }
        }
    }
    // Domain name was fully parsed
    // Overwrite last '.' written with NULL byte
    *(domain_name + (--current_length)) = '\0';
    // Shrink allocated memory to fit domain name, if needed
    if (current_length + 1 < max_length) {
        domain_name = (char *) realloc(domain_name, sizeof(char) * (current_length + 1));
    }
    // Advance offset after NULL terminator, if domain name compression was not used
    if (!compression) {
        (*offset)++;
    }
    return domain_name;
}

/**
 * Parse a DNS Question section.
 * 
 * @param qdcount the number of questions present in the question section
 * @param data a pointer pointing to the start of the DNS message
 * @param offset a pointer to the current parsing offset
 * @return the parsed question section
 */
dns_question_t* dns_parse_questions(uint16_t qdcount, uint8_t *data, uint16_t *offset) {
    // Init
    dns_question_t *questions = (dns_question_t *) malloc(qdcount * sizeof(dns_question_t));
    // Iterate over all questions
    for (uint16_t i = 0; i < qdcount; i++) {
        // Parse domain name
        (questions + i)->qname = dns_parse_domain_name(data, offset);
        // Parse rtype and rclass
        (questions + i)->qtype = ntohs(*((uint16_t *) (data + *offset)));
        (questions + i)->qclass = ntohs(*((uint16_t *) (data + *offset + 2)));
        *offset += 4;
    }
    return questions;
}

/**
 * Parse a DNS Resource Record RDATA field.
 * 
 * @param rdlength the length, in bytes, of the RDATA field
 * @param data a pointer pointing to the start of the DNS message
 * @param offset a pointer to the current parsing offset
 * @return the parsed RDATA field
 */
static rdata_t dns_parse_rdata(dns_rr_type_t rtype, uint16_t rdlength, uint8_t *data, uint16_t *offset) {
    rdata_t rdata;
    if (rdlength == 0) {
        // RDATA field is empty
        rdata.data = NULL;
    } else {
        // RDATA field is not empty
        switch (rtype) {
            case A:
                // RDATA contains an IPv4 address
                rdata.ipv4 = *((uint32_t *) (data + *offset));  // Stored in network byte order
                *offset += rdlength;
                break;
            case NS:
            case CNAME:
            case PTR:
                // RDATA contains is a domain name
                rdata.domain_name = dns_parse_domain_name(data, offset);
                break;
            default:
                // RDATA contains is generic data
                rdata.data = (uint8_t *) malloc(sizeof(char) * rdlength);
                memcpy(rdata.data, data + *offset, rdlength);
                *offset += rdlength;
        }
    }
    return rdata;
}

/**
 * Parse a DNS Resource Record list.
 * @param count the number of resource records present in the section
 * @param data a pointer pointing to the start of the DNS message
 * @param offset a pointer to the current parsing offset
 * @return the parsed resource records list
 */
dns_resource_record_t* dns_parse_rrs(uint16_t count, uint8_t *data, uint16_t *offset) {
    dns_resource_record_t *rrs = (dns_resource_record_t *) malloc(count * sizeof(dns_resource_record_t));
    for (uint16_t i = 0; i < count; i++) {
        // Parse domain name
        (rrs + i)->name = dns_parse_domain_name(data, offset);
        // Parse rtype, rclass and TTL
        dns_rr_type_t rtype = ntohs(*((uint16_t *) (data + *offset)));
        (rrs + i)->rtype = rtype;
        (rrs + i)->rclass = ntohs(*((uint16_t *) (data + *offset + 2)));
        (rrs + i)->ttl = ntohl(*((uint32_t *) (data + *offset + 4)));
        // Parse rdata
        uint16_t rdlength = ntohs(*((uint16_t *) (data + *offset + 8)));
        (rrs + i)->rdlength = rdlength;
        *offset += 10;
        (rrs + i)->rdata = dns_parse_rdata(rtype, rdlength, data, offset);
    }
    return rrs;
}

/**
 * Parse a DNS message.
 * 
 * @param data a pointer to the start of the DNS message
 * @return the parsed DNS message
 */
dns_message_t dns_parse_message(uint8_t *data) {
    // Init
    dns_message_t message;
    uint16_t offset = 0;
    // Parse DNS header
    message.header = dns_parse_header(data, &offset);
    // If present, parse DNS Question section
    if (message.header.qdcount > 0) {
        message.questions = dns_parse_questions(message.header.qdcount, data, &offset);
    }
    // If present, parse DNS Answer section
    if (message.header.ancount > 0) {
        message.answers = dns_parse_rrs(message.header.ancount, data, &offset);
    }
    // If present, parse DNS Authority section
    if (message.header.nscount > 0) {
        message.authorities = dns_parse_rrs(message.header.nscount, data, &offset);
    }
    // If present, parse DNS Additional section
    if (message.header.arcount > 0) {
        message.additionals = dns_parse_rrs(message.header.arcount, data, &offset);
    }
    return message;
}


///// LOOKUP /////

/**
 * @brief Search for a specific domain name in a DNS Questions list.
 * 
 * @param questions DNS Questions list
 * @param qdcount number of Suestions in the list
 * @param domain_name the domain name to search for
 * @return true if the domain name is found in the Questions list, false otherwise
 */
bool dns_contains_domain_name(dns_question_t *questions, uint16_t qdcount, char *domain_name) {
    for (uint16_t i = 0; i < qdcount; i++) {
        if (strcmp((questions + i)->qname, domain_name) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Search for a specific domain name in a DNS Questions list.
 * 
 * @param questions DNS Questions list
 * @param qdcount number of Suestions in the list
 * @param domain_name the domain name to search for
 * @return the DNS Question related to the given domain name, or NULL if not found
 */
dns_question_t* dns_get_question(dns_question_t *questions, uint16_t qdcount, char *domain_name) {
    for (uint16_t i = 0; i < qdcount; i++) {
        if (strcmp((questions + i)->qname, domain_name) == 0) {
            return questions + i;
        }
    }
    return NULL;
}

/**
 * @brief Retrieve the IP addresses corresponding to a given domain name in a DNS Answers list.
 * 
 * Searches a DNS Answer list for a specific domain name and returns the corresponding IP address.
 * Processes each Answer recursively if the Answer Type is a CNAME.
 * 
 * @param answers DNS Answers list to search in
 * @param ancount number of Answers in the list
 * @param domain_name domain name to search for
 * @return struct ip_list representing the list of corresponding IP addresses
 */
ip_list_t dns_get_ip_from_name(dns_resource_record_t *answers, uint16_t ancount, char *domain_name) {
    ip_list_t ip_list;
    ip_list.ip_count = 0;
    ip_list.ip_addresses = NULL;
    char *cname = domain_name;
    for (uint16_t i = 0; i < ancount; i++) {
        if (strcmp((answers + i)->name, cname) == 0) {
            if ((answers + i)->rtype == A) {
                if (ip_list.ip_addresses == NULL) {
                    ip_list.ip_addresses = (uint32_t*) malloc(sizeof(uint32_t));
                } else {
                    ip_list.ip_addresses = realloc(ip_list.ip_addresses, ip_list.ip_count + 1);
                }
                *(ip_list.ip_addresses + ip_list.ip_count) = (answers + i)->rdata.ipv4;
                ip_list.ip_count++;
            } else if ((answers + i)->rtype == CNAME) {
                cname = (answers + i)->rdata.domain_name;
            }
        }
    }
    return ip_list;
}


///// PRINTING /////

/**
 * Print a DNS header.
 * 
 * @param message the DNS header
 */
void dns_print_header(dns_header_t header) {
    printf("DNS Header:\n");
    printf("  ID: %#hx\n", header.id);
    printf("  Flags: %#hx\n", header.flags);
    printf("  QR: %d\n", header.qr);
    printf("  Questions count: %hd\n", header.qdcount);
    printf("  Answers count: %hd\n", header.ancount);
    printf("  Authority name servers count: %hd\n", header.nscount);
    printf("  Additional records count: %hd\n", header.arcount);
}

/**
 * Print a DNS Question
 * 
 * @param question the DNS Question
 */
void dns_print_question(dns_question_t question) {
    printf("  Question:\n");
    printf("    Domain name: %s\n", question.qname);
    printf("    Type: %hd\n", question.qtype);
    printf("    Class: %hd\n", question.qclass);
}

/**
 * Print a DNS Question section.
 * 
 * @param qdcount the number of Questions in the Question section
 * @param questions the list of DNS Questions
 */
void dns_print_questions(uint16_t qdcount, dns_question_t *questions) {
    printf("DNS Question section:\n");
    for (uint16_t i = 0; i < qdcount; i++) {
        dns_print_question(*(questions + i));
    }
}

/**
 * Return a string representation of the given RDATA value.
 * 
 * @param rtype the type corresponding to the RDATA value
 * @param rdlength the length, in bytes, of the RDATA value
 * @param rdata the RDATA value, stored as a union type
 * @return a string representation of the RDATA value
 */
char* dns_rdata_to_str(dns_rr_type_t rtype, uint16_t rdlength, rdata_t rdata) {
    if (rdlength == 0) {
        // RDATA is empty
        return "";
    }
    switch (rtype) {
        case A:
            // RDATA is an IPv4 address
            return ipv4_net_to_str(rdata.ipv4);
            break;
        case NS:
        case CNAME:
        case PTR:
            // RDATA is a domain name
            return rdata.domain_name;
            break;
        default: ;
            // Generic RDATA
            char *buffer = (char *) malloc(rdlength * 4 + 1);  // Allocate memory for each byte (4 characters) + the NULL terminator
            for (uint8_t i = 0; i < rdlength; i++) {
                snprintf(buffer + (i * 4), 5, "\\x%02x", *(rdata.data + i));
            }
            return buffer;
    }
}

/**
 * Print a DNS Resource Record.
 * 
 * @param section_name the name of the Resource Record section
 * @param rr the DNS Resource Record
 */
void dns_print_rr(char* section_name, dns_resource_record_t rr) {
    printf("  %s RR:\n", section_name);
    printf("    Name: %s\n", rr.name);
    printf("    Type: %hd\n", rr.rtype);
    printf("    Class: %hd\n", rr.rclass);
    printf("    TTL [s]: %d\n", rr.ttl);
    printf("    Data length: %hd\n", rr.rdlength);
    printf("    RDATA: %s\n", dns_rdata_to_str(rr.rtype, rr.rdlength, rr.rdata));
}

/**
 * Print a DNS Resource Records section.
 * 
 * @param section_name the name of the Resource Record section
 * @param count the number of Resource Records in the section
 * @param rrs the list of DNS Resource Records
 */
void dns_print_rrs(char* section_name, uint16_t count, dns_resource_record_t *rrs) {
    printf("%s RRs:\n", section_name);
    for (uint16_t i = 0; i < count; i++) {
        dns_print_rr(section_name, *(rrs + i));
    }
}

/**
 * Print a DNS message.
 * 
 * @param message the DNS message
 */
void dns_print_message(dns_message_t message) {
    dns_print_header(message.header);
    dns_print_questions(message.header.qdcount, message.questions);
    dns_print_rrs("Answer", message.header.ancount, message.answers);
    dns_print_rrs("Authority", message.header.nscount, message.authorities);
    dns_print_rrs("Additional", message.header.arcount, message.additionals);
}
