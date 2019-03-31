#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

int
main(void) {
	FILE *file;
	unsigned char flag[128];
	unsigned char correct_hash[20] = {
		0x4a, 0xc9, 0xb0, 0x57, 0xf8, 0x02, 0x12, 0x60, 0x6c, 0xea,
		0xab, 0xf3, 0xc6, 0x50, 0x5d, 0xaf, 0xed, 0x40, 0xa4, 0x50
	};
	unsigned char password[20];

	printf("Insert your password: ");
	scanf("%37s", password);

	printf("\n%d\t%s\n", strlen((char *)password), password);
	printf("%d\t%s\n", strlen((char *)correct_hash), correct_hash);

	SHA1(password, strlen((char *)password), password);

	printf("%d\t%s\n", strlen((char *)password), password);
	printf("%d\n", memcmp(password, correct_hash, 20));

	if(memcmp(password, correct_hash, 20) == 0) {
		printf("CORRECT PASSWORD!\n");
		file = fopen("/challenges/overshade/flag", "r");
		if(file != NULL) {
			fscanf(file, "%s", flag);
			fclose(file);
			printf("Flag: %s\n", flag);
		} else {
			printf("Error while opening the flag file\n");
		}
	} else {
		printf("WRONG PASSWORD!\n");
	}
	fflush(stdout);

	return 0;
}
