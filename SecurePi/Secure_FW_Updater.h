#pragma once
// Basic Header
#include <stdio.h>
#include <stdlib.h>

// TPM Header
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_error.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>

// OpenSSL Header
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define SIGN_KEY_UUID {0, 0, 0, 0, 0, {0, 0, 0, 1, 1}}
#define DBG(message, tResult) printf("(Line%d, %s) %s returned 0x%08x. %s.\n\n",__LINE__ ,__func__ , message, tResult, (char *)Trspi_Error_String(tResult));
#define DEBUG 1

void TPM_ERROR_PRINT(int res, char* msg);
void dividestr(char* dest, char* source, int start, int end);
int get_hash_value(unsigned char* xor_result);
int release_nvram();
int generate_signature();
int check_firmware_version(char* version);
int receiveData(BIO *sbio, unsigned char* sign, char *version);
int verify_firmware_signature(unsigned char* sign);
int fwupdater();