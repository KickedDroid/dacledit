#include <ldap.h>
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LDAP_DEPRECATED 1

int modify_dacl(const char* ldap_uri, const char* ccache_path,
                const char* target_dn, const char* new_sd) {
    LDAP *ld;
    int rc;
    
    // Set the KRB5CCNAME environment variable
    setenv("KRB5CCNAME", ccache_path, 1);

    // Initialize LDAP connection
    rc = ldap_initialize(&ld, ldap_uri);
    if (rc != LDAP_SUCCESS) {
        fprintf(stderr, "ldap_initialize failed: %s\n", ldap_err2string(rc));
        return 1;
    }

    // Set LDAP version to 3
    int version = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    // Set up SASL defaults
    rc = ldap_set_option(ld, LDAP_OPT_X_SASL_MECH, "GSSAPI");
    if (rc != LDAP_SUCCESS) {
        fprintf(stderr, "Failed to set SASL mechanism: %s\n", ldap_err2string(rc));
        ldap_unbind_ext_s(ld, NULL, NULL);
        return 1;
    }

    // Perform SASL GSSAPI bind
    rc = ldap_sasl_interactive_bind_s(ld, NULL, "GSSAPI", NULL, NULL, LDAP_SASL_QUIET, NULL, NULL);
    if (rc != LDAP_SUCCESS) {
        fprintf(stderr, "SASL GSSAPI bind failed: %s\n", ldap_err2string(rc));
        ldap_unbind_ext_s(ld, NULL, NULL);
        return 1;
    }

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
        fprintf(stderr, "ldap_modify_ext_s failed: %s\n", ldap_err2string(rc));
        ldap_unbind_ext_s(ld, NULL, NULL);
        return 1;
    }

    printf("DACL modified successfully\n");

    // Unbind from LDAP server
    ldap_unbind_ext_s(ld, NULL, NULL);
    return 0;
}