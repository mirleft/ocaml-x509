#!/bin/sh

curve="secp521r1"
file="p521.pem"

openssl ecparam -name $curve -genkey -noout -out priv_$file
openssl ec -in priv_$file -pubout -out pub_$file

openssl ec -in priv_$file -no_public -out priv_$file.2
openssl pkcs8 -in priv_$file.2 -nocrypt -topk8 -out priv_$file
rm priv_$file.2
