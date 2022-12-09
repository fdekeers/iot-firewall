/**
 * @file src/parsers/http.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief HTTP message parser
 * @date 2022-09-19
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "http.h"


///// PARSING /////

/**
 * @brief Parse the method of an HTTP message.
 * 
 * Parse a HTTP message to retrieve its method,
 * and convert it to a http_message_t.
 * Only the two first characters need to be parsed.
 * Advances the offset value after parsing.
 * 
 * @param data pointer to the start of the HTTP message
 * @param offset current offset in the message
 * @return parsed HTTP method
 */
static http_method_t http_parse_method(uint8_t *data, uint16_t *offset) {
    switch (*(data + *offset)) {
    case 'G':
        // Method is GET
        *offset += 4;
        return GET;
        break;
    case 'H':
        // Method is HEAD
        *offset += 5;
        return HEAD;
        break;
    case 'P':
        // Method is POST or PUT
        switch (*(data + *offset + 1)) {
        case 'O':
            // Method is POST
            *offset += 5;
            return POST;
            break;
        case 'U':
            // Method is PUT
            *offset += 4;
            return PUT;
            break;
        default:
            // Unknown method
            return HTTP_UNKNOWN;
        }
    case 'D':
        // Method is DELETE
        *offset += 7;
        return DELETE;
        break;
    case 'C':
        // Method is CONNECT
        *offset += 8;
        return CONNECT;
        break;
    case 'O':
        // Method is OPTIONS
        *offset += 8;
        return OPTIONS;
        break;
    case 'T':
        // Method is TRACE
        *offset += 6;
        return TRACE;
        break;
    default:
        // Unknown method
        return HTTP_UNKNOWN;
    }
}

/**
 * @brief Parse an URI in an HTTP message.
 * 
 * Parse a HTTP message to retrieve its URI,
 * and convert it to a character string.
 * Advances the offset value after parsing.
 * 
 * @param data pointer to the start of the HTTP message
 * @param offset current offset in the message
 * @return parsed URI
 */
static char* http_parse_uri(uint8_t *data, uint16_t *offset) {
    uint16_t length = 1;
    uint16_t max_length = HTTP_METHOD_MAX_LEN;
    char *uri = (char *) malloc(sizeof(char) * max_length);
    while (*(data + *offset) != ' ') {
        if (length == max_length) {
            // URI is too long, increase buffer size
            max_length *= 2;
            uri = (char *) realloc(uri, sizeof(char) * max_length);
        }
        *(uri + (length - 1)) = *(data + (*offset)++);
        length++;
    }
    if (length < max_length) {
        // URI is shorter than allocated buffer, shrink buffer
        uri = (char *) realloc(uri, sizeof(char) * length);
    }
    // Add NULL terminating character
    *(uri + length - 1) = '\0';
    return uri;
}

/**
 * @brief Parse the method and URI of HTTP message.
 * 
 * @param data pointer to the start of the HTTP message
 * @param dst_port TCP destination port
 * @return the parsed HTTP message
 */
http_message_t http_parse_message(uint8_t *data, uint16_t dst_port) {
    http_message_t message;
    message.is_request = dst_port == 80;
    uint16_t offset = 0;
    message.method = http_parse_method(data, &offset);
    if (message.is_request)
        message.uri = http_parse_uri(data, &offset);
    else
        message.uri = NULL;
    return message;
}


///// DESTROY /////

/**
 * @brief Free the memory allocated for a HTTP message.
 *
 * @param message the HTTP message to free
 */
void http_destroy_message(http_message_t message) {
    if (message.uri != NULL)
        free(message.uri);
}


///// PRINTING /////

/**
 * @brief Converts a HTTP method from enum value to character string.
 * 
 * @param method the HTTP method in enum value
 * @return the same HTTP method as a character string
 */
char* http_method_to_str(http_method_t method) {
    switch (method) {
    case GET:
        return "GET";
        break;
    case HEAD:
        return "HEAD";
        break;
    case POST:
        return "POST";
        break;
    case PUT:
        return "PUT";
        break;
    case DELETE:
        return "DELETE";
        break;
    case CONNECT:
        return "CONNECT";
        break;
    case OPTIONS:
        return "OPTIONS";
        break;
    case TRACE:
        return "TRACE";
        break;
    default:
        return "UNKNOWN";
    }
}

/**
 * @brief Print the method and URI of a HTTP message.
 * 
 * @param message the message to print
 */
void http_print_message(http_message_t message) {
    printf("HTTP message:\n");
    printf("  is request ?: %d\n", message.is_request);
    printf("  Method: %s\n", http_method_to_str(message.method));
    printf("  URI: %s\n", message.uri);
}
