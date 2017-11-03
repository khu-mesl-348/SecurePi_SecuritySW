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

void TPM_ERROR_PRINT(int res, char* msg)
{
#if DEBUG
	DBG(msg, res);
#endif
	if (res != 0) exit(1);
}

void dividestr(char* dest, char* source, int start, int end)
{
	int i, j = 0;

	for (i = start; i < end; i++)
		dest[j++] = source[i];
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

	// image.fit hash start
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

int release_nvram()
{
	TSS_HCONTEXT hContext;
	TSS_RESULT result;
	TSS_HPOLICY hNVPolicy;
	TSS_HNVSTORE hNVStore;

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

	result = Tspi_NV_ReleaseSpace(hNVStore);
	TPM_ERROR_PRINT(result, "Release NVRAM Space\n");

	result = Tspi_Policy_FlushSecret(hNVPolicy);
	TPM_ERROR_PRINT(result, "Flush NVPolicy Secret\n");

	result = Tspi_Context_FreeMemory(hContext, NULL);
	TPM_ERROR_PRINT(result, "Free TPM Memory\n");

	result = Tspi_Context_Close(hContext);
	TPM_ERROR_PRINT(result, "Close TPM\n");

	return 0;
}

int generate_signature()
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
	UINT32 srk_authusage, signLen;
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

	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, MY_UUID, &hSigning_key);
	TPM_ERROR_PRINT(result, "Load the Signing Key\n");

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

int check_firmware_version(char* version)
{
	TSS_HCONTEXT hContext;
	TSS_RESULT result;
	TSS_HNVSTORE hNVStore;
	BYTE *data;
	UINT32 datasize = 256;

	int i;
	char preversion[4] = "";

	result = Tspi_Context_Create(&hContext);
	TPM_ERROR_PRINT(result, "Create TPM Context\n");

	result = Tspi_Context_Connect(hContext, NULL);
	TPM_ERROR_PRINT(result, "Connect to TPM\n");

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0, &hNVStore);
	TPM_ERROR_PRINT(result, "Create NVRAM Object\n");

	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_INDEX, 0, 2);
	TPM_ERROR_PRINT(result, "Set NVRAM Index\n");

	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_DATASIZE, 0, 256);
	TPM_ERROR_PRINT(result, "Set NVRAM Data Size\n");

	result = Tspi_NV_ReadValue(hNVStore, 0, &datasize, &data);
	TPM_ERROR_PRINT(result, "Read Signature in NVRAM\n");

	for (i = 0; i < 256; i = i + 3)
	{
		int start = 0;
		int end = 3;
		dividestr(preversion, data, start, end);

		if (strcmp(version, preversion) == 0)
		{
			result = Tspi_Context_FreeMemory(hContext, NULL);
			TPM_ERROR_PRINT(result, "Free TPM Memory\n");

			result = Tspi_Context_Close(hContext);
			TPM_ERROR_PRINT(result, "Close TPM\n");

			printf("Version Check Fail\n\n");
			return 1;
		}
		else
		{
			start = end;
			end = end + 3;
		}
	}

	printf("Version Check Success\n\n");
	result = Tspi_Context_FreeMemory(hContext, NULL);
	TPM_ERROR_PRINT(result, "Free TPM Memory\n");

	result = Tspi_Context_Close(hContext);
	TPM_ERROR_PRINT(result, "Close TPM\n");

	return 0;
}

int receiveData(BIO *sbio, unsigned char* sign, char *version)
{
	int len;
	FILE* fp;
	char buf[2048];
	char data[2048];
	char fileLen[4][10];
	char* token = NULL;
	int i, start, end;
	char verBuf[4] = "";

	for (i = 0; i < 4; i++)
		memset(fileLen[i], 0, 10);
	memset(data, 0, 2048);

	// Data Rececive Start
	while ((len = BIO_read(sbio, buf, 2048)) != 0);

	token = strtok(buf, "  ");
	strcpy(fileLen[0], token);

	token = strtok(NULL, "  ");
	strcpy(fileLen[1], token);

	token = strtok(NULL, "  ");
	strcpy(fileLen[2], token);

	token = strtok(NULL, "  ");
	strcpy(fileLen[3], token);

	token = strtok(NULL, "");
	strcpy(data, token);

	memset(buf, 0, 2048);
	start = 1;
	end = 4;
	dividestr(buf, data, start, end);
	strcpy(verBuf, buf);

	// Store New Bootloader
	if (!(fp = fopen("Boot", "wb")))
	{
		printf("Boot Open Fail\n");
		return 1;
	}

	memset(buf, 0, 2048);
	start = end;
	end = start + atoi(fileLen[0]);
	dividestr(buf, data, start, end);
	fwrite((void*)buf, 1, atoi(fileLen[0]), fp);

	fclose(fp);

	// Store New Firmware
	if (!(fp = fopen("Firmware", "wb")))
	{
		printf("Firmware Open Fail\n");
		return 1;
	}

	memset(buf, 0, 2048);
	start = end;
	end = start + atoi(fileLen[1]);
	dividestr(buf, data, start, end);
	fwrite((void*)buf, 1, atoi(fileLen[1]), fp);

	fclose(fp);

	// Store Certificate
	if (!(fp = fopen("Cert", "wb")))
	{
		printf("Cert Open Fail\n");
		return 1;
	}

	memset(buf, 0, 2048);
	start = end;
	end = start + atoi(fileLen[2]);
	dividestr(buf, data, start, end);
	fwrite((void*)buf, 1, atoi(fileLen[2]), fp);
	fclose(fp);

	memset(buf, 0, 2048);
	start = end;
	end = start + atoi(fileLen[3]);
	dividestr(buf, data, start, end);
	strcpy(sign, buf);

	strcpy(version, verBuf);

	return 0;
}

int verify_firmware_signature(unsigned char* sign)
{
	// SHA Value
	SHA_CTX ctx;
	char sha1_result[SHA_DIGEST_LENGTH];
	unsigned char buf[256];
	int i;

	// Decrypt Value
	FILE* fp;
	char decrypt_sign[20];
	int decrypt_signlen;
	X509* user_x509 = NULL;
	RSA* pub_key = NULL;
	EVP_PKEY* e_pub_key = NULL;

	// Extract Public Key
	if (!(fp = fopen("Cert", "rb")))
	{
		printf("Cert Open Error\n");
		return 1;
	}

	user_x509 = PEM_read_X509(fp, NULL, NULL, NULL);
	e_pub_key = X509_get_pubkey(user_x509);
	pub_key = EVP_PKEY_get1_RSA(e_pub_key);

	fclose(fp);

	// Decrypt Signature
	decrypt_signlen = RSA_public_decrypt(256, sign, (unsigned char*)decrypt_sign, pub_key, RSA_PKCS1_PADDING);

	if (decrypt_signlen < 1)
	{
		printf("Signature Decryption Fail\n");
		return 1;
	}
	else
		printf("Signature Decryption Success\n");

	// Hash New Firmware
	if (!(fp = fopen("Firmware", "rb")))
	{
		printf("Firmware Open Fail\n");
		return 1;
	}

	SHA1_Init(&ctx);
	while ((i = fread(buf, 1, sizeof(buf), fp)) > 0)
		SHA1_Update(&ctx, buf, i);
	SHA1_Final(sha1_result, &ctx);

	fclose(fp);

	// Verify New Firmware
	if (!memcmp(decrypt_sign, sha1_result, 20))
		printf("New Firmware Verification Success\n");
	else
	{
		printf("New Firmware Verification Fail\n");
		return 1;
	}

	return 0;
}

int fwupdater()
{
	char version[4];

	// Signature Value
	unsigned char sign[256];

	// SSL Value
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *sbio, *out;
	BIO *bio_err = 0;
	int len, res;

	// SSL Connection Start
	if (!bio_err)
	{
		SSL_library_init();
		SSL_load_error_strings();
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	}

	ctx = SSL_CTX_new(SSLv23_client_method());
	sbio = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(sbio, &ssl);

	if (!ssl)
	{
		fprintf(stderr, "Can't locate SSL pointer\n");
		exit(1);
	}

	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	BIO_set_conn_hostname(sbio, "163.180.118.145:4000");
	out = BIO_new_fp(stdout, BIO_NOCLOSE);

	res = BIO_do_connect(sbio);
	if (res <= 0)
	{
		fprintf(stderr, "Error connecting to server\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	res = BIO_do_handshake(sbio);
	if (res <= 0)
	{
		fprintf(stderr, "Error establishing SSL connection \n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	else
		printf("SSL Connection Success\n");

	// Receive Firmware
	memset(sign, 0, 256);
	if (receiveData(sbio, sign, version) != 0)
	{
		printf("Data receive failed\n");
		return 1;
	}

	// Verify Firmware Signature
	if (verify_firmware_signature(sign) != 0)
	{
		printf("Firmware_Signature decryption failed\n");
		return 1;
	}

	// Check Firmware Version
	if (check_firmware_version(version) != 0)
	{
		printf("Firmware Version is not correct\n");
		return 1;
	}

	if (release_nvram() != 0)
	{
		printf("Release NVRAM Fail\n");
		return 1;
	}

	if (generate_signature() != 0)
	{
		printf("Signature generation failed\n");
		return 1;
	}

	printf("==================================\n");
	printf("              FINISH              \n");
	printf("==================================\n");

	return 0;
}
