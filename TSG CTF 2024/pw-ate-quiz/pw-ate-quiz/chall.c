#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void crypting(long long* secret, size_t len, long long key) {
	for (int i = 0; i < (len - 1) / 8 + 1; i++) {
		secret[i] = secret[i] ^ key;
	}
}

void output_flag() {
	char flag[100];
	FILE *fd = fopen("./flag.txt", "r");
	if (fd == NULL) {
		puts("Could not open \"flag.txt\"");
		exit(1);
	}
	fscanf(fd, "%99s", flag);
	printf("%s\n", flag);
}

int main() {
	setvbuf(stdout, NULL, _IONBF, 0);

	char hints[3][8] = {"Hint1:T", "Hint2:S", "Hint3:G"};
	char password[0x20];
	char input[0x20];
	

	srand(time(0));
	long long key = ((long long)rand() << 32) | rand();

	FILE *fd = fopen("password.txt", "r");
	if (fd == NULL) {
		puts("Could not open \"password.txt\"");
		exit(1);
	}

	fscanf(fd, "%31s", password);
	size_t length = strlen(password);
	crypting((long long*)password, 0x20, key);

	printf("Enter the password > ");
	scanf("%31s", input);

	crypting((long long*)input, 0x20, key);

	if (memcmp(password, input, length + 1) == 0) {
		puts("OK! Here's the flag!");
		output_flag();
		exit(0);
	}

	puts("Authentication failed.");
	puts("You can get some hints.");
	
	while (1) {
		int idx;
		printf("Enter a hint number (0~2) > ");
		if (scanf("%d", &idx) == 1 && idx >= 0) {
			for (int i = 0; i < 8; i++) {
				putchar(hints[idx][i]);
			}
			puts("");
		} else {
			break;
		}
	}

	while (getchar()!='\n');

	printf("Enter the password > ");
	scanf("%31s", input);

	crypting((long long*)input, 0x20, key);

	if (memcmp(password, input, length + 1) == 0) {
		puts("OK! Here's the flag!");
		output_flag();
	} else {
		puts("Authentication failed.");
	}

	return 0;
}
