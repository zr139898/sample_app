// common.c -- defines our error reporting function handle_error.
// Also defines a function that will perform common initialization
// such as setting up OpenSSL for multithreading,
// initializing the library, and loading error strings.

#include "common.h"

void handle_error(const char * file, int lineno, const char * msg) {
    fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
    ERR_print_errors_fp(stderr);
    exit(-1);
}

void init_OpenSSL(void) {
    if (!THREAD_setup() || SSL_library_init()) {
        fprintf(stderr, "** OpenSSL initialization failed!\n");
        exit(-1);
    }
    SSL_load_error_strings();
}

