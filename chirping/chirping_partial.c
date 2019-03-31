...

int
check(void) {
	unsigned int attempt, p_len, c;
	unsigned char hash[16], pwd[32];

	/* allow 3 attempts */
 	for(attempt=1; attempt<=3; attempt++) {
		printf("[%d] Please enter the password: ", attempt);
		fflush(stdout);
		/* reset the password */
		bzero(pwd, 32);
		p_len = 0;
		/* read password */
		while(p_len <= MAX_P_LEN) {
			c = getchar();
			pwd[p_len] = c;
			if(c == '\n')
				break;
			p_len++;
		}
		MD5(pwd, p_len, hash);
		if(memcmp(hash, correct_hash, 16) == 0) {
			return 1;
		} else {
			printf("[%d] Invalid password %s", attempt, pwd);
			fflush(stdout);
		}
	}

	return 0;
}
 
...
