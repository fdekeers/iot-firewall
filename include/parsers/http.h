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
 * Useful fields of a HTTP message
 */
typedef struct http_message {
    http_method_t method;
    char *uri;
} http_message_t;


////////// FUNCTIONS //////////

///// PARSING /////

http_message_t http_parse_message(uint8_t *data);


///// PRINTING /////

void http_print_message(http_message_t message);


#endif /* _IOTFIREWALL_HTTP_ */
