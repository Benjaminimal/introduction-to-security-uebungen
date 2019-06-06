#!/bin/bash

ENCFOLDER='messages'
PLAINFOLDER='messages'
KEYFOLDER='privkeys'

[ -d "${PLAINFOLDER}" ] || mkdir "${PLAINFOLDER}"

for key in $(ls $KEYFOLDER); do
    user=${key%.*}
    cat "$ENCFOLDER/$user.enc" | openssl rsautl -decrypt -inkey "$KEYFOLDER/$key"
done
