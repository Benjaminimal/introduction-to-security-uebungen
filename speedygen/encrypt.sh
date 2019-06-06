#!/bin/bash

ENCFOLDER='messages'
FLAG=$(cat flag.txt)

# Check if the users file has been provided.
if [[ "${#}" -ne 1 ]]; then
    echo '[!] Missing users file!'
    echo '[*] Usage: ./encrypt.sh PATH_USERS_FILE'
    exit 1
fi

# Create the directory where to store the encrypted messages if it doesn't exist
[ -d "${ENCFOLDER}" ] || mkdir "${ENCFOLDER}"

# Encrypt a slightly different message for each user that contains the flag
for user in $(cat $1); do
    msg="Hi ${user}, don't reveal this to anybody: ${FLAG}!"
    echo -n "${msg}" | openssl rsautl -encrypt -pubin -inkey "pubkeys/${user}.pem" -out "${ENCFOLDER}/${user}.enc"
done
