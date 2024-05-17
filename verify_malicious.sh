#!/bin/bash

chmod 777 "$1"

# Verificăm dacă numărul de linii este mai mic de 3 și numărul de cuvinte depășește 1000
# și numărul de caractere depășește 2000
if [ $(wc -l < "$1") -lt 3 ] && [ $(wc -w < "$1") -gt 1000 ] && [ $(wc -c < "$1") -gt 2000 ]; then
    echo "$1"
    chmod 0000 "$1"
    exit 1
fi  

#verificam daca fisierul contine caractere non-ASCII
if grep -qP '[^\x00-\x7F]' "$1"; then
    echo "$1"
    chmod 0000 "$1"
    exit 1
fi

#verificam daca fisierul exista

if grep -q -i -e "corrupted" -e "dangerous" -e "risk" -e "attack" -e "malware" -e "malicious" "$1"; then
        echo "$1"
        chmod 0000 "$1"
        exit 1
fi

echo "SAFE"
chmod 0000 "$1"
exit 2
