// Basic Header
#include <stdio.h>
#include <stdlib.h>

// TPM Header
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>
#include <tss/tss_error.h>

#define DBG(message, tResult) printf("(Line%d, %s) %s returned 0x%08x. %s.\n\n",__LINE__ ,__func__ , message, tResult, (char *)Trspi_Error_String(tResult));
#define DEBUG 1

void TPM_ERROR_PRINT(int res, char* msg)
{
#if DEBUG
    DBG(msg, res);
#endif
    if (res != 0) exit(1);
}

int main(void)
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

    result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_INDEX, 0, 2);
    TPM_ERROR_PRINT(result, "Set NVRAM Index\n");

    result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_PERMISSIONS, 0, TPM_NV_PER_OWNERWRITE);
    TPM_ERROR_PRINT(result, "Set NVRAM Attribute\n");

    result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_DATASIZE, 0, 256);
    TPM_ERROR_PRINT(result, "Set NVRAM Data Size\n");

    result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hNVPolicy);
    TPM_ERROR_PRINT(result, "Set NVRAM Policy\n");

    result = Tspi_NV_ReleaseSpace(hNVStore);
    TPM_ERROR_PRINT(result, "Release NVRAM Space\n");

    result = Tspi_NV_DefineSpace(hNVStore, 0, 0);
    TPM_ERROR_PRINT(result, "Create NVRAM Space\n");

    result = Tspi_NV_WriteValue(hNVStore, 0, 3, "111");
    TPM_ERROR_PRINT(result, "Write Signature in NVRAM\n");

    result = Tspi_Policy_FlushSecret(hNVPolicy);
    TPM_ERROR_PRINT(result, "Flush NVPolicy Secret\n");

    result = Tspi_Context_FreeMemory(hContext, NULL);
    TPM_ERROR_PRINT(result, "Free TPM Memory\n");

    result = Tspi_Context_Close(hContext);
    TPM_ERROR_PRINT(result, "Close TPM\n");

    return 0;
}
