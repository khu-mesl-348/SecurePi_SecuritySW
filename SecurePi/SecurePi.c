#include <stdio.h>

#include "Secure_Boot_Daemon.h"
#include "Secure_FW_Updater.h"
#include "Remote_Attestation_Prover.h"

int main(void)
{
	if (Secure_Boot_Daemon() != 0)
	{
		printf("Secure Boot Fail\n");
		return 1;
	}
	else
		printf("Secure Boot Success\n");

	if (fwupdater() != 0)
	{
		printf("Secure FW Update Fail\n");
		return 1;
	}
	else
		printf("Secure FW Update Success\n");

	if (prover() != 0)
	{
		printf("Remote Attestation Fail\n");
		return 1;
	}
	else
		printf("Remote Attestation Success\n");

	return 0;
}