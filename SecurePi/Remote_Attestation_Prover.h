#pragma once
// Basic Header
#include <stdio.h>
#include <string.h>

// TPM Header
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <tss/tss_error.h>
#include <trousers/trousers.h>

// OpenSSL Header
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define DBG(message, tResult) printf("(Line%d, %s) %s returned 0x%08x. %s.\n\n",__LINE__ ,__func__ , message, tResult, (char *)Trspi_Error_String(tResult));
#define DEBUG 1

void TPM_ERROR_PRINT(int res, char* msg);
int generate_hash_extend(char* extendValue);
int createAIK();
EVP_PKEY *load();
int sendData(BIO* sbio, unsigned char* sign);
int receiveData(BIO* sbio, char* recvData);
int generate_signature(char* extendValue, unsigned char* sign);
int prover(void);