#include <ldap.h>
#include <krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_gss_error(OM_uint32 major_status, OM_uint32 minor_status);


int modify_dacl(const char* ldap_uri, const char* ccache_path,
                const char* target_dn, const char* new_sd) {
    LDAP *ld = NULL;
    int rc = LDAP_SUCCESS;
    int result = 1;  // Default to failure
    char *error_msg = NULL;
    krb5_context krb_context = NULL;
    krb5_ccache ccache = NULL;
    OM_uint32 major_status, minor_status;
    gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;
    gss_name_t target_name = GSS_C_NO_NAME;
    gss_buffer_desc input_name = GSS_C_EMPTY_BUFFER;
    gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
    
    
    printf("[DEBUG] Starting modify_dacl function\n");
    printf("[DEBUG] LDAP URI: %s\n", ldap_uri);
    printf("[DEBUG] CCcache path: %s\n", ccache_path);
    printf("[DEBUG] Target DN: %s\n", target_dn);
    printf("[DEBUG] New SD: %s\n", new_sd);

    // Initialize Kerberos context
    rc = krb5_init_context(&krb_context);
    if (rc) {
        fprintf(stderr, "[ERROR] Failed to initialize Kerberos context: %s\n", krb5_get_error_message(krb_context, rc));
        goto cleanup;
    }
    printf("[DEBUG] Kerberos context initialized\n");

    // Resolve and open the ccache
    rc = krb5_cc_resolve(krb_context, ccache_path, &ccache);
    if (rc) {
        fprintf(stderr, "[ERROR] Failed to resolve ccache: %s\n", krb5_get_error_message(krb_context, rc));
        goto cleanup;
    }
    printf("[DEBUG] CCcache resolved\n");

    // Get credentials from ccache
    gss_key_value_element_desc element;
    gss_key_value_set_desc cred_store;

    element.key = "ccache";
    element.value = ccache_path;
    cred_store.count = 1;
    cred_store.elements = &element;

    major_status = gss_acquire_cred_from(&minor_status, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                         GSS_C_NO_OID_SET, GSS_C_INITIATE, &cred_store, &creds, NULL, NULL);
    if (major_status != GSS_S_COMPLETE) {
        fprintf(stderr, "[ERROR] Failed to acquire credentials from ccache\n");
        goto cleanup;
    }
    printf("[DEBUG] Acquired credentials from ccache\n");

    // Initialize LDAP connection
    rc = ldap_initialize(&ld, ldap_uri);
    if (rc != LDAP_SUCCESS) {
        fprintf(stderr, "[ERROR] ldap_initialize failed: %s\n", ldap_err2string(rc));
        goto cleanup;
    }
    printf("[DEBUG] LDAP connection initialized\n");

    // Set LDAP version to 3
    int version = LDAP_VERSION3;
    rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (rc != LDAP_SUCCESS) {
        fprintf(stderr, "[ERROR] Failed to set LDAP version: %s\n", ldap_err2string(rc));
        goto cleanup;
    }
    printf("[DEBUG] LDAP version set to 3\n");

    // Parse the LDAP URI to get the hostname
    char *hostname = strstr(ldap_uri, "://");
    if (hostname == NULL) {
        fprintf(stderr, "[ERROR] Invalid LDAP URI format\n");
        goto cleanup;
    }
    hostname += 3;  // Skip past "://"

    // Remove any port number if present
    char *colon = strchr(hostname, ':');
    if (colon) {
        *colon = '\0';
    }

    // Construct the correct SPN
    char spn[256];
    snprintf(spn, sizeof(spn), "ldap/%s", hostname);
    printf("[DEBUG] Using SPN: %s\n", spn);

    // Prepare the target name for GSS-API
    input_name.value = spn;
    input_name.length = strlen(spn);

    // Import the name
    major_status = gss_import_name(&minor_status, &input_name, GSS_C_NT_USER_NAME, &target_name);
    if (major_status != GSS_S_COMPLETE) {
        fprintf(stderr, "[ERROR] Failed to import GSS name: ");
        print_gss_error(major_status, minor_status);
        goto cleanup;
    }

    // Perform GSS-API Kerberos authentication
    OM_uint32 req_flags = GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;


    // Use the GSS-API token for LDAP bind
    struct berval *servcred;
    
    struct berval cred;
    cred.bv_val = (char *)output_token.value;
    cred.bv_len = output_token.length;


    do {
        rc = ldap_sasl_bind_s(ld, NULL, "GSSAPI", &cred, NULL, NULL, &servcred);
        
        if (rc == LDAP_SASL_BIND_IN_PROGRESS) {
            // If we received a challenge, we need to get a new token from GSS-API
            if (servcred) {
                input_token.value = servcred->bv_val;
                input_token.length = servcred->bv_len;
                ber_bvfree(servcred);
            }
            
            major_status = gss_init_sec_context(&minor_status,
                                        creds,
                                        &gss_context,
                                        target_name,
                                        GSS_C_NO_OID,
                                        req_flags,
                                        0,
                                        GSS_C_NO_CHANNEL_BINDINGS,
                                        &input_token,
                                        NULL,
                                        &output_token,
                                        NULL,
                                        NULL);

            if (major_status != GSS_S_COMPLETE && major_status != GSS_S_CONTINUE_NEEDED) {
                fprintf(stderr, "[ERROR] gss_init_sec_context failed: ");
                print_gss_error(major_status, minor_status);
                goto cleanup;
            }
            // Prepare the new token for the next iteration
            cred.bv_val = (char *)output_token.value;
            cred.bv_len = output_token.length;
            printf("[DEBUG] %s\n", cred.bv_val);
        }
    } while (rc == LDAP_SASL_BIND_IN_PROGRESS);

    if (rc != LDAP_SUCCESS) {
        fprintf(stderr, "LDAP bind failed: %s\n", ldap_err2string(rc));
        // Handle error...
    } else {
        printf("[DEBUG] LDAP bind successful\n");
    }

    printf( "Server credentials: %s\n", servcred->bv_val );



    // Prepare the modification
    LDAPMod mod, *mods[2];
    char *values[2];
    values[0] = (char*)new_sd;
    values[1] = NULL;

    mod.mod_op = LDAP_MOD_REPLACE;
    mod.mod_type = "nTSecurityDescriptor";
    mod.mod_values = values;

    mods[0] = &mod;
    mods[1] = NULL;

    // Perform the modification
    rc = ldap_modify_ext_s(ld, target_dn, mods, NULL, NULL);
    if (rc != LDAP_SUCCESS) {
        ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &error_msg);
        fprintf(stderr, "[ERROR] ldap_modify_ext_s failed: %s (%s)\n", 
                ldap_err2string(rc), error_msg ? error_msg : "No additional info");
        goto cleanup;
    }

    printf("[SUCCESS] DACL modified successfully\n");
    result = 0;  // Success

cleanup:
    if (krb_context) {
        if (ccache) {
            krb5_cc_close(krb_context, ccache);
            printf("[DEBUG] CCcache closed\n");
        }
        krb5_free_context(krb_context);
        printf("[DEBUG] Kerberos context freed\n");
    }
    if (error_msg) {
        ldap_memfree(error_msg);
    }
    if (ld) {
        ldap_unbind_ext_s(ld, NULL, NULL);
        printf("[DEBUG] LDAP connection unbound\n");
    }
    if (gss_context != GSS_C_NO_CONTEXT) {
        gss_delete_sec_context(&minor_status, &gss_context, GSS_C_NO_BUFFER);
    }
    if (target_name != GSS_C_NO_NAME) {
        gss_release_name(&minor_status, &target_name);
    }
    if (creds != GSS_C_NO_CREDENTIAL) {
        gss_release_cred(&minor_status, &creds);
    }
    gss_release_buffer(&minor_status, &output_token);
    return result;
}


// Implementation of print_gss_error function
void print_gss_error(OM_uint32 major_status, OM_uint32 minor_status) {
    OM_uint32 message_context = 0;
    gss_buffer_desc status_string;

    do {
        OM_uint32 tmp_major = gss_display_status(
            &tmp_major,
            major_status,
            GSS_C_GSS_CODE,
            GSS_C_NO_OID,
            &message_context,
            &status_string
        );

        if (GSS_ERROR(tmp_major)) {
            fprintf(stderr, "Error in gss_display_status\n");
            break;
        }

        fprintf(stderr, "%.*s\n", (int)status_string.length, (char *)status_string.value);
        gss_release_buffer(&tmp_major, &status_string);

    } while (message_context != 0);

    message_context = 0;
    do {
        OM_uint32 tmp_major = gss_display_status(
            &tmp_major,
            minor_status,
            GSS_C_MECH_CODE,
            GSS_C_NO_OID,
            &message_context,
            &status_string
        );

        if (GSS_ERROR(tmp_major)) {
            fprintf(stderr, "Error in gss_display_status\n");
            break;
        }

        fprintf(stderr, "%.*s\n", (int)status_string.length, (char *)status_string.value);
        gss_release_buffer(&tmp_major, &status_string);

    } while (message_context != 0);
}

