#include <security/pam_modules.h>
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <security/pam_ext.h>
#include <syslog.h>


size_t discard_response(void *ptr, size_t size, size_t nmemb, void *data) {
    // This function does nothing and discards the response
    return size * nmemb;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    if (argc != 3) {
        syslog(LOG_ERR, "pam_keycloak: Invalid number of arguments");
        return PAM_SYSTEM_ERR;
    }


    int pam_code;
    char *username = NULL;
    char *password = NULL;

    pam_code = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &username, "Username: ");
    if (pam_code != PAM_SUCCESS) {
        syslog(LOG_ERR, "pam_keycloak: Can not get username");
        return PAM_AUTHINFO_UNAVAIL;
    }

    pam_code = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &password, "Password: ");
    if (pam_code != PAM_SUCCESS) {
        syslog(LOG_ERR, "pam_keycloak: Can not get password");
        return PAM_AUTHINFO_UNAVAIL;
    }

    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        syslog(LOG_ERR, "pam_keycloak: Can not initialise curl");
        return PAM_SYSTEM_ERR;
    }

    char *escaped_password = curl_easy_escape(curl, password, (int) strlen(password));
    if (escaped_password == NULL) {
        syslog(LOG_ERR, "pam_keycloak: Can not escape password");
        return PAM_SYSTEM_ERR;
    }

    char *post_fields;
    asprintf(&post_fields, "grant_type=password&client_id=%s&client_secret=%s&username=%s&password=%s",
             argv[1], argv[2], username, escaped_password);

    curl_easy_setopt(curl, CURLOPT_URL, argv[0]);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK) {
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

        if (response_code == 200) {
            return PAM_SUCCESS;
        }
        return PAM_AUTH_ERR;
    }

    return PAM_SYSTEM_ERR;
}
