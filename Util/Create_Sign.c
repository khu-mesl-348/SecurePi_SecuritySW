// Basic Header
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// TPM Header
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>
#include <tss/tss_error.h>

// OpenSSL Header
#include <openssl/sha.h>

#define SIGN_KEY_UUID {0, 0, 0, 0, 0, {0, 0, 0, 1, 1}}
#define DBG(message, tResult) printf("(Line%d, %s) %s returned 0x%08x. %s.\n\n",__LINE__ ,__func__ , message, tResult, (char *)Trspi_Error_String(tResult));
#define DEBUG 1

void TPM_ERROR_PRINT(int res, char* msg)
{
#if DEBUG
	DBG(msg, res);
#endif
	if (res != 0) exit(1);
}

int get_hash_value(unsigned char* xor_result)
{
    FILE* fp;
    int i, j;
    unsigned char buf[256];

	// SHA1 Value
	SHA_CTX ctx;
	char sha1_result[3][SHA_DIGEST_LENGTH];

	// SecurePi Serial Number Value
	char serial[16 + 1];

	// Buffer Init
	for (i = 0; i < 3; i++)
		memset(sha1_result[i], 0, 20);
	memset(buf, 0, sizeof(buf));
	memset(serial, 0, sizeof(serial));

    // u-boot hash start
    if(!(fp=fopen("/boot/u-boot.bin", "rb")))
    {
        printf("/boot/u-boot.bin Open Fail\n");
        return 1;
    }

    SHA1_Init(&ctx);
    while((i = fread(buf, 1, sizeof(buf), fp)) > 0)
        SHA1_Update(&ctx, buf, i);
    SHA1_Final(sha1_result[0], &ctx);

    fclose(fp);

    // image.fit hash start
	memset(buf, 0, sizeof(buf));

	if (!(fp = fopen("/boot/image.fit", "rb")))
	{
		printf("/boot/image.fit Open Fail\n");
		return 1;
	}

    SHA1_Init(&ctx);
    while((i = fread(buf, 1, sizeof(buf), fp)) > 0)
        SHA1_Update(&ctx, buf, i);
    SHA1_Final(sha1_result[1], &ctx);

    fclose(fp);

	// Hash SecurePi Serial Number
	memset(buf, 0, sizeof(buf));

	if (!(fp = fopen("/proc/cpuinfo", "r")))
	{
		printf("/proc/cpuinfo Open Fail\n");
		return 1;
	}

	SHA1_Init(&ctx);

	while (fgets(buf, 256, fp))
		if (strncmp(buf, "Serial", 6) == 0)
			strcpy(serial, strchr(buf, ':') + 2);

	SHA1_Update(&ctx, serial, sizeof(serial));
	SHA1_Final(sha1_result[2], &ctx);

	fclose(fp);

	for (i = 0; i < 3; i++)
		for (j = 0; j < SHA_DIGEST_LENGTH; j++)
			xor_result[j] = xor_result[j] ^ sha1_result[i][j];

    return 0;
}

int main(void)
{
    TSS_HCONTEXT hContext;
    TSS_RESULT result;
    TSS_HKEY hSRK, hSigning_key;
    TSS_HPOLICY hSRKPolicy, hNVPolicy;
    TSS_UUID MY_UUID = SIGN_KEY_UUID;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    TSS_FLAG initFlags = TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
    TSS_HHASH hHash;
    TSS_HNVSTORE hNVStore;
    BYTE *sign;
    UINT32 signLen;
    FILE* fp;
	unsigned char xor_result[20];

	memset(xor_result, 0, 20);
    result = Tspi_Context_Create(&hContext);
	TPM_ERROR_PRINT(result, "Create TPM Context\n");

    result = Tspi_Context_Connect(hContext, NULL);
	TPM_ERROR_PRINT(result, "Connect to TPM\n");

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hSigning_key);
	TPM_ERROR_PRINT(result, "Create the Signing key Object\n");

    result = Tspi_SetAttribUint32(hSigning_key, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_SIGSCHEME, TSS_SS_RSASSAPKCS1V15_SHA1);
	TPM_ERROR_PRINT(result, "Set the Signing key's Padding Type\n");

    result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	TPM_ERROR_PRINT(result, "Get SRK Handle\n");

    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
	TPM_ERROR_PRINT(result, "Get SRK Policy Object\n");

    result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
	TPM_ERROR_PRINT(result, "Set SRK Secret\n");

	result = Tspi_Key_CreateKey(hSigning_key, hSRK, 0);
	TPM_ERROR_PRINT(result, "Create the Signing Key\n");

	result = Tspi_Key_LoadKey(hSigning_key, hSRK);
	TPM_ERROR_PRINT(result, "Load the Signing Key Context\n");

	result = Tspi_Context_RegisterKey(hContext, hSigning_key, TSS_PS_TYPE_SYSTEM, MY_UUID, TSS_PS_TYPE_SYSTEM, SRK_UUID);
	TPM_ERROR_PRINT(result, "Register the Signing Key\n");

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_SHA1, &hHash);
	TPM_ERROR_PRINT(result, "Create Hash Object\n");

	// Hash Start
	get_hash_value(xor_result);

    result = Tspi_Hash_SetHashValue(hHash, 20, xor_result);
	TPM_ERROR_PRINT(result, "Set Hash Value for Generating Signature\n");

    result = Tspi_Hash_Sign(hHash, hSigning_key, &signLen, &sign);
	TPM_ERROR_PRINT(result, "Generate Signature\n");

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0, &hNVStore);
	TPM_ERROR_PRINT(result, "Create NVRAM Object\n");

    result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_INDEX, 0, 1);
	TPM_ERROR_PRINT(result, "Set NVRAM Index\n");

    result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_PERMISSIONS, 0, TPM_NV_PER_OWNERWRITE);
	TPM_ERROR_PRINT(result, "Set NVRAM Attribute\n");

    result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_DATASIZE, 0, 256);
	TPM_ERROR_PRINT(result, "Set NVRAM Data Size\n");

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hNVPolicy);
	TPM_ERROR_PRINT(result, "Set NVRAM Policy\n");

    result = Tspi_NV_DefineSpace(hNVStore, 0, 0);
	TPM_ERROR_PRINT(result, "Create NVRAM Space\n");

    result = Tspi_NV_WriteValue(hNVStore, 0, signLen, sign);
	TPM_ERROR_PRINT(result, "Write Signature in NVRAM\n");

    result = Tspi_Policy_FlushSecret(hSRKPolicy);
	TPM_ERROR_PRINT(result, "Flush SRKPolicy Secret\n");

	result = Tspi_Policy_FlushSecret(hNVPolicy);
	TPM_ERROR_PRINT(result, "Flush NVPolicy Secret\n");

    result = Tspi_Context_FreeMemory(hContext, NULL);
	TPM_ERROR_PRINT(result, "Free TPM Memory\n");

    result = Tspi_Context_Close(hContext);
	TPM_ERROR_PRINT(result, "Close TPM\n");

    return 0;
}
