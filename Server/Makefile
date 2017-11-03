Secure_FW_Update_Server: Secure_FW_Update_Server.o
	gcc -o Secure_FW_Update_Server Secure_FW_Update_Server.o -lssl -lcrypto

Secure_FW_Update_Server.o: Secure_FW_Update_Server.c
	gcc -c Secure_FW_Update_Server.c

Remote_Attestation_Server: Remote_Attestation_Server.o
	gcc -o Remote_Attestation_Server Remote_Attestation_Server.o -lssl -lcrypto

Remote_Attestation_Server.o: Remote_Attestation_Server.c
	gcc -c Remote_Attestation_Server.c

clean:
	rm -f Remote_Attestation_Server Remote_Attestation_Server.o
