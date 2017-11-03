Create_Sign: Create_Sign.o
	gcc -o Create_Sign Create_Sign.o -ltspi -lssl -lcrypto

Create_Sign.o: Create_Sign.c
	gcc -c Create_Sign.c

Firmware_Version_Initialization: Firmware_Version_Initialization.o
	gcc -o Firmware_Version_Initialization Firmware_Version_Initialization.o -ltspi

Firmware_Version_Initialization.o: Firmware_Version_Initialization.c
	gcc -c Firmware_Version_Initialization.c

Release_TPM_Data: Release_TPM_Data.o
	gcc -o Release_TPM_Data Release_TPM_Data.o -ltspi

Release_TPM_Data.o: Release_TPM_Data.c
	gcc -c Release_TPM_Data.c

clean:
	rm -f Create_Sign Create_Sign.o Firmware_Version_Initialization Firmware_Version_Initialization.o Firmware_Version_Initialization Firmware_Version_Initialization.o
