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

void TPM_ERROR_PRINT(int res, char* msg)
{
#if DEBUG
	DBG(msg, res);
#endif
	if (res != 0) exit(1);
}

char get_plain(unsigned char ch) {
	ch = ch % 26;
	return (char)(97 + (ch) % 26);
}

void createSRK(unsigned char* xor_result, unsigned char* SRK_PASSWD) {
	int i;
	for (i = 0; i < 20; i++)
		SRK_PASSWD[i] = get_plain(xor_result[i]);
}

int get_hash_value(unsigned char* xor_result) {
	FILE *fp;
	int i, j;
	unsigned char buf[256];

	// SHA1 Value
	SHA_CTX ctx;
	char sha1_result[3][SHA_DIGEST_LENGTH];

	// SecurePi Serial Number Value
	char serial[16+1];

	// Hash u-boot.bin
	for (i = 0; i < 3; i++)
		memset(sha1_result[i], 0, sizeof(sha1_result[i]));
	memset(buf, 0, sizeof(buf));
	memset(serial, 0, sizeof(serial));

	if (!(fp = fopen("/boot/u-boot.bin", "rb")))
	{
		printf("/boot/u-boot.bin Open Fail\n");
		return 1;
	}

	SHA1_Init(&ctx);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0)
		SHA1_Update(&ctx, buf, i);
	SHA1_Final(sha1_result[0], &ctx);

	fclose(fp);

	// Hash image.fit
	memset(buf, 0, sizeof(buf));

	if (!(fp = fopen("/boot/image.fit", "rb")))
	{
		printf("/boot/image.fit Open Fail\n");
		return 1;
	}

	SHA1_Init(&ctx);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0)
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

int verify_Bootloader_Signature(unsigned char* xor_result)
{
	TSS_HCONTEXT hContext;
	TSS_RESULT result;
	TSS_HKEY hSRK, hSigning_Key;
	TSS_HPOLICY hSRKPolicy, hNVPolicy;
	TSS_UUID MY_UUID = SIGN_KEY_UUID;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;
	TSS_FLAG initFlags = TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
	TSS_HHASH hHash;
	TSS_HNVSTORE hNVStore;
	BYTE *data;
	UINT32 dataLen = 256, srk_authusage;

	result = Tspi_Context_Create(&hContext);
	TPM_ERROR_PRINT(result, "Create TPM Context\n");

	result = Tspi_Context_Connect(hContext, NULL);
	TPM_ERROR_PRINT(result, "Connect to TPM\n");

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

	result = Tspi_NV_ReadValue(hNVStore, 0, &dataLen, &data);
	TPM_ERROR_PRINT(result, "Read Signature in NVRAM\n");

	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	TPM_ERROR_PRINT(result, "Get SRK Handle\n");

	result = Tspi_GetAttribUint32(hSRK, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, &srk_authusage);
	TPM_ERROR_PRINT(result, "Get SRK Attribute\n");

	if (srk_authusage)
	{
		result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
		TPM_ERROR_PRINT(result, "Get SRK Policy\n");

		result = Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
		TPM_ERROR_PRINT(result, "Set SRK Secret\n");
	}

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hSigning_Key);
	TPM_ERROR_PRINT(result, "Create the Signing key Object\n");

	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, MY_UUID, &hSigning_Key);
	TPM_ERROR_PRINT(result, "Load the Signing Key\n");

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_SHA1, &hHash);
	TPM_ERROR_PRINT(result, "Create Hash Object\n");

	result = Tspi_Hash_SetHashValue(hHash, 20, xor_result);
	TPM_ERROR_PRINT(result, "Set Hash Value for Verifying Signature\n");

	result = Tspi_Hash_VerifySignature(hHash, hSigning_Key, 256, data);
	TPM_ERROR_PRINT(result, "Verify Signature\n");

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

int setSRK(unsigned char* xor_result, unsigned char* SRK_PASSWD)
{
	TSS_HTPM hTPM;
	TSS_HPOLICY hTPMPolicy, hNewPolicy;
	TSS_HCONTEXT hContext;
	TSS_RESULT result;
	TSS_HKEY hSRK;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;

	createSRK(xor_result, SRK_PASSWD);

	result = Tspi_Context_Create(&hContext);
	TPM_ERROR_PRINT(result, "Create TPM Context\n");

	result = Tspi_Context_Connect(hContext, NULL);
	TPM_ERROR_PRINT(result, "Connect to TPM\n");

	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	TPM_ERROR_PRINT(result, "Get TPM Object\n");

	result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTPMPolicy);
	TPM_ERROR_PRINT(result, "Get TPM Policy\n");

	result = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_PLAIN, 1, "1");
	TPM_ERROR_PRINT(result, "Set SRK Secret\n");

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hNewPolicy);
	TPM_ERROR_PRINT(result, "Create New SRK Object\n");

	result = Tspi_Policy_SetSecret(hNewPolicy, TSS_SECRET_MODE_PLAIN, 10, SRK_PASSWD);
	TPM_ERROR_PRINT(result, "Set New SRK Password\n");

	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	TPM_ERROR_PRINT(result, "Get SRK Handle\n");

	result = Tspi_ChangeAuth(hSRK, hTPM, hNewPolicy);
	TPM_ERROR_PRINT(result, "Set New SRK Password\n");

	return 0;
}

int Secure_Boot_Daemon()
{
	unsigned char xor_result[20];
	unsigned char SRK_PASSWD[20];

	memset(xor_result, 0, 20);
	memset(SRK_PASSWD, 0, 20);

	if (get_hash_value(xor_result) != 0)
	{
		printf("Hash Fail\n");
		return 1;
	}

	if (verify_Bootloader_Signature(xor_result) != 0)
	{
		printf("Verify Signature Fail\n");
		return 1;
	}
	else
		printf("Verify Signature Success\n");

	if (setSRK(xor_result, SRK_PASSWD) != 0)
	{
		printf("Set SRK Fali\n");
		return 1;
	}

    return 0;
}