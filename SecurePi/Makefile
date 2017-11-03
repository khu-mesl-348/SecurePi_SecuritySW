SecurePi: Secure_Boot_Daemon.o Secure_FW_Updater.o Remote_Attestation_Prover.o
	gcc -o SecurePi Secure_Boot_Daemon.o Secure_FW_Updater.o Remote_Attestation_Prover.o -ltspi -lcrypto -lssl

Secure_Boot_Daemon.o: Secure_Boot_Daemon.c
	gcc -c Secure_Boot_Daemon.c

Secure_FW_Updater.o: Secure_FW_Updater.c
	gcc -c Secure_FW_Updater.c

Remote_Attestation_Prover.o: Remote_Attestation_Prover.c
	gcc -c Remote_Attestation_Prover.c

clean:
	rm -f Secure_Boot_Daemon Secure_Boot_Daemon.o Secure_FW_Updater Secure_FW_Updater.o Remote_Attestation_Prover Remote_Attestation_Prover.o