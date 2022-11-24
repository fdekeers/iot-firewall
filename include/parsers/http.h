/**
 * @file include/parsers/http.h
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief HTTP message parser
 * @date 2022-09-09
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _IOTFIREWALL_HTTP_
#define _IOTFIREWALL_HTTP_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define HTTP_METHOD_MAX_LEN 7      // Maximum length of a HTTP method
#define HTTP_URI_DEFAULT_LEN 100   // Default length of a HTTP URI


/**
 * HTTP methods
 */
typedef enum {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    UNKNOWN
} http_method_t;

/**
 * Abstraction of a HTTP message
 */
typedef struct http_message {
    bool is_request;       // True if the message is a request, false if it is a response
    http_method_t method;  // HTTP method (GET, POST, etc.)
    char *uri;             // Message URI
} http_message_t;


////////// FUNCTIONS //////////

///// PARSING /////

/**
 * @brief Parse the method and URI of HTTP message.
 * 
 * @param data pointer to the start of the HTTP message
 * @param src_port TCP destination port
 * @return the parsed HTTP message
 */
http_message_t http_parse_message(uint8_t *data, uint16_t dst_port);


///// PRINTING /////

/**
 * @brief Converts a HTTP method from enum value to character string.
 * 
 * @param method the HTTP method in enum value
 * @return the same HTTP method as a character string
 */
char* http_method_to_str(http_method_t method);

/**
 * @brief Print the method and URI of a HTTP message.
 * 
 * @param message the message to print
 */
void http_print_message(http_message_t message);


#endif /* _IOTFIREWALL_HTTP_ */
