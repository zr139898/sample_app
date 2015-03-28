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
    if (!THREAD_setup() || !SSL_library_init()) {
        fprintf(stderr, "** OpenSSL initialization failed!\n");
        exit(-1);
    }
    SSL_load_error_strings();
}

void seed_prng(void) {
    RAND_load_file("/dev/urandom", 1024);
}

// This callback employs several functions from the X509 family of functions
// to report the detailed error info.
int verify_callback(int preverify_ok, X509_STORE_CTX * ctx) {
    char data[256];

    if (!preverify_ok) {
        X509 * cert = X509_STORE_CTX_get_current_cert(ctx);
        int depth = X509_STORE_CTX_get_error_depth(ctx);
        int err = X509_STORE_CTX_get_error(ctx);

        fprintf(stderr, "-Error with certificate at depth: %i\n", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        fprintf(stderr, "  issuer   = %s\n", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        fprintf(stderr, "  subject  = %s\n", data);
        fprintf(stderr, "  err %i:%s\n", err, X509_verify_cert_error_string(err));
    }
    return preverify_ok;
}

// post_connection_check is implemented as a wrapper around
// SSL_get_verify_result, which performs our extra peer cert checks.
// It uses the reserved error code X509_V_ERR_APPLICATION_VERIFICATION to
// indicate errors where there is no peer cert present or the cert presented
// does not match the expected FQDN.
// This function will return an error in the following circumstances:
// * If no peer cert is found
// * If it is called with a NULL second argument, i.e., if no FQDN is specified
//   to compare against.
// * If the dNSName fields found (if any) do not match the host arg and the
//   commonName also doesn't match the host arg (if found)
// * Any time the SSL_get_verify_result routine returns an error
// Otherwise, X509_V_OK will be returned.
long post_connection_check(SSL * ssl, char * host) {
    X509 * cert;
    X509_NAME * subj;
    char data[256];
    int extcount;
    int ok = 0;

    // Checking the return from SSL_get_peer_certificate here is not
    // structly necessary. With our example program, it is not possible
    // for it to return NULL. However, it is good form to check the
    // return since it can return NULL if the examples are modified
    // to enable anonymous ciphers or for the server to not require
    // a client certificate.
    if (!(cert = SSL_get_peer_certificate(ssl)) || !host)
        goto err_occurred;
    if ((extcount  = X509_get_ext_count(cert)) > 0) {
        int i;
        // iterate through the extensions and use the extension-specific
        // parsing routes to find all extensions that are subjectAltName field.
        for (i = 0; i < extcount; i++) {
            char * extstr;  // hold the extracted short name of extension
            X509_EXTENSION * ext;

            ext = X509_get_ext(cert, i);
            extstr = (char *)OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));
            if (!strcmp(extstr, "subjectAltName")) {
                int j;
                unsigned char * data;
                STACK_OF(CONF_VALUE) * val;
                CONF_VALUE * nval;
                X509V3_EXT_METHOD * meth;
                void * ext_str = NULL;
                // extract the X509V3_EXT_METHOD object from the extension.
                // This object is a container of extension-specific function
                // for manipulating the data within the extension.
                if (!(meth = X509V3_EXT_get(ext)))
                    break;
                data = ext->value->data;
                // d2i and i2v functions convert the raw data in subjectAleName
                // to a stack of CONF_VALUE objects. This is neccessary to make
                // it simple to iterate over the several kinds of fields in the
                // subjectAltName so that we may find the dNSName field(s).
#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
                if (meth->it)
                    ext_str = ASN1_item_d2i(NULL, &data, ext->value->length,
                                            ASN1_ITEM_ptr(meth->it));
                else
                    ext_str = meth->d2i(NULL, &data, ext->value->length);
#else
                ext_str = meth->d2i(NULL, &data, ext->value->length);
#endif
                val = meth->i2v(meth, ext_str, NULL);
                // Since a subjectAltName field may itself contain several
                // fields, we must then iterate to find any dNSName fields.
                // We check each member of this CONF_VALUE stack to see if we
                // have a match for the host string in a dNSName field.
                for (j = 0; j < sk_CONF_VALUE_num(val); j++) {
                    nval = sk_CONF_VALUE_value(val, j);
                    if (!strcmp(nval->name, "DNS") && !strcmp(nval->value, host))
                    {
                        ok = 1;
                        break;
                    }
                }
            }
            // As soon as we find a match (host), we stop the iterations over
            // all the extensions.
            if (ok)
                break;
        }
    }
    // pursue checking the commonName of the certificate if no match is found
    // in a dNSName field.
    if (!ok && (subj = X509_get_subject_name(cert)) &&
        X509_NAME_get_text_by_NID(subj, NID_commonName, data, 256) > 0) {
        data[255] = 0;
        if (strcasecmp(data, host) != 0)
            goto err_occurred;
    }
    X509_free(cert);
    return SSL_get_verify_result(ssl);

err_occurred:
    if (cert)
        X509_free(cert);
    return X509_V_ERR_APPLICATION_VERIFICATION;
}

