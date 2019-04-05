#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#define NAME_LENGTH 16
#define MAX_TIME    5
#define LEN_CAPTCHA 8
#define NUM_CAPTCHA 100000000
#define CHAR_HEIGHT 5
#define CHAR_LENGTH 3
#define ROW_LENGTH  ((CHAR_LENGTH + 1) * LEN_CAPTCHA - 1)
#define FLAG_PREFIX 16

char digits[][CHAR_HEIGHT][CHAR_LENGTH] = {
    {    /* 0 */
        {'*','*','*'},
        {'*',' ','*'},
        {'*',' ','*'},
        {'*',' ','*'},
        {'*','*','*'}
    },
    {    /* 1 */
        {' ','*',' '},
        {' ','*',' '},
        {' ','*',' '},
        {' ','*',' '},
        {' ','*',' '}
    },
    {    /* 2 */
        {'*','*','*'},
        {' ',' ','*'},
        {'*','*','*'},
        {'*',' ',' '},
        {'*','*','*'}
    },
    {    /* 3 */
        {'*','*','*'},
        {' ',' ','*'},
        {' ','*','*'},
        {' ',' ','*'},
        {'*','*','*'}
    },
    {    /* 4 */
        {'*',' ','*'},
        {'*',' ','*'},
        {'*','*','*'},
        {' ',' ','*'},
        {' ',' ','*'}
    },
    {    /* 5 */
        {'*','*','*'},
        {'*',' ',' '},
        {'*','*','*'},
        {' ',' ','*'},
        {'*','*','*'}
    },
    {    /* 6 */
        {'*','*','*'},
        {'*',' ',' '},
        {'*','*','*'},
        {'*',' ','*'},
        {'*','*','*'}
    },
    {
         /* 7 */
        {'*','*','*'},
        {' ',' ','*'},
        {' ',' ','*'},
        {' ',' ','*'},
        {' ',' ','*'}
    },
    {    /* 8 */
        {'*','*','*'},
        {'*',' ','*'},
        {'*','*','*'},
        {'*',' ','*'},
        {'*','*','*'}
    },
    {    /* 9 */
        {'*','*','*'},
        {'*',' ','*'},
        {'*','*','*'},
        {' ',' ','*'},
        {'*','*','*'}
    }
};

/* String literals */
char msg_error[]		= "[!] Can't open the %s file. Aborting...\n";
char msg_banner[]		= "Welcome %s. Show me that you're fast enough to solve %d captcha in %d seconds. "
							"If you succeed, I'll give you a piece of my precious flag.\n";
char msg_name[]			= "What's your name? ";
char msg_numcaptcha[]	= "\n[*] Captcha %d / %d\n\n";
char msg_question[]		= "\nWhat is the captcha? ";
char msg_ok[]			= "[*] Correct!\n";
char msg_nope[]			= "[!] Wrong! :(\n";
char msg_welldone[]		= "[*] Well done! Here is a piece of the flag: ";
char msg_fail[]			= "[!] No flag for you. You're too slow!\n";

void
init_seed(void) {
	unsigned int seed;
	int fd;

	fd = open("seed", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, msg_error, "seed");
		exit(EXIT_FAILURE);
	}

	read(fd, &seed, sizeof(seed));
	seed *= (unsigned int) time(NULL);
	srand(seed);
	close(fd);
}

void
clear_captcha(char captcha[CHAR_HEIGHT][ROW_LENGTH]) {
	int r, c;

	for (r = 0; r < CHAR_HEIGHT; r++) {
		for (c = 0; c < ROW_LENGTH; c++) {
			captcha[r][c] = ' ';
		}
	}
}

void
write_digit(char captcha[CHAR_HEIGHT][ROW_LENGTH], int digit, int column) {
	int r, c;

	for (r = 0; r < CHAR_HEIGHT; r++) {
		for (c = 0; c < CHAR_LENGTH; c++) {
			captcha[r][c+column] = digits[digit][r][c];
		}
	}
}

int
ask_new_captcha(int n) {
	int i, j, digit, number, answer, error;
	char c, captcha[CHAR_HEIGHT][ROW_LENGTH];

	number = 0;
	clear_captcha(captcha);
	for (i = 0; i < LEN_CAPTCHA; i++) {
		digit = rand() % 10;
		number = number * 10 + digit;
		write_digit(captcha, digit, i*(CHAR_LENGTH+1));
	}
	
	printf(msg_numcaptcha, n, NUM_CAPTCHA);
	for (i = 0; i < CHAR_HEIGHT; i++) {
		for (j = 0; j < ROW_LENGTH; j++) {
			putchar(captcha[i][j]);
		}
		putchar('\n');
	}
	printf(msg_question);
	fflush(stdout);

	answer = error = 0;
	do {
		c = getchar();
		if (c >= '0' && c <= '9') {
			answer = answer * 10 + c - '0';	
		} else if (c != '\n') {
			error = 1;
		}
	} while (c != '\n');
	
	if (!error && number == answer) {
		printf(msg_ok);
		return 1;
	} else {
		printf(msg_nope);
		return 0;
	}
}

void
welcome_banner(void) {
	char name[NAME_LENGTH];

	printf(msg_name);
	fflush(stdout);
	scanf("%[^\n]s", name);
	getchar();

	printf(msg_banner, name, NUM_CAPTCHA, MAX_TIME);
}

int
captcha_challenge(void) {
	time_t start_time;
	int correct_answers;

	correct_answers = 0;
	start_time = time(NULL);
	while (correct_answers < NUM_CAPTCHA && difftime(time(NULL), start_time) <= MAX_TIME) {
		correct_answers += ask_new_captcha(correct_answers + 1);
	}
	if (difftime(time(NULL), start_time) > MAX_TIME) {
		correct_answers--;
	}
	return correct_answers == NUM_CAPTCHA;
}

void
print_flag(void) {
	int i, fd;
	char c;

	fd = open("flag", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, msg_error, "flag");
		exit(EXIT_FAILURE);
	}
	for (i = 0; i < FLAG_PREFIX; i++) {
		read(fd, &c, sizeof(char));
		putchar(c);
	}
	close(fd);
	putchar('\n');
}

int
main(void) {
	init_seed();
	welcome_banner();
	if (captcha_challenge()) {
		printf(msg_welldone);
		print_flag();
	} else {
		printf(msg_fail);
	}
	return EXIT_SUCCESS;
}
