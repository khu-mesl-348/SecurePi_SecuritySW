#pragma once
// Basic Header //
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// FIFO Header -> Share SRK PW //
#include <sys/types.h>
#include <sys/stat.h>

// TPM Header //
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <tss/tss_error.h>
#include <trousers/trousers.h>

// OpenSSL Header -> For SHA //
#include <openssl/sha.h>

// Define Value
#define SIGN_KEY_UUID {0, 0, 0, 0, 0, {0, 0, 0, 1, 1}}
#define DBG(message, tResult) printf("(Line%d, %s) %s returned 0x%08x. %s.\n\n",__LINE__ ,__func__ , message, tResult, (char *)Trspi_Error_String(tResult));
#define DEBUG 1

void TPM_ERROR_PRINT(int res, char* msg);
char get_plain(unsigned char ch);
void createSRK(unsigned char* xor_result, unsigned char* SRK_PASSWD);
int get_hash_value(unsigned char* xor_result);
int verify_Bootloader_Signature(unsigned char* xor_result);
int setSRK(unsigned char* xor_result, unsigned char* SRK_PASSWD);
int Secure_Boot_Daemon();