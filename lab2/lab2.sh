#!/bin/bash
echo "Lab2 Grader"
echo "tls.py is at $1"
echo "lab2.cert is at $2"
echo "lab2.key is at $3"
echo "cert authority pem is at $4"
pipenv run python $1 9000 8000 $2 $3 &
pid=$!
sleep 5
openssl s_client -CAfile $4 -debug -connect cs361s.utexas.lab2:9000 -verify_return_error > out.txt &
sleep 5
kill $pid
pkill openssl

if grep "SSL handshake has read 0 bytes" out.txt
then
   echo "Test Failed: No connection made"
elif grep -x "Verification: OK" out.txt
then
   echo "Test Passed"
else
   echo "Test Failed: Cert not verified"
fi
rm out.txt
