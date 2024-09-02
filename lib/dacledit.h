#ifndef DACLEDIT_H
#define DACLEDIT_H

int modify_dacl(const char* ldap_uri, const char* bind_dn, const char* bind_pw,
                const char* target_dn, const char* new_sd);

#endif // DACLEDIT_H