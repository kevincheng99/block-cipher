Contributor
===========
Name: Christopher Nguyen
Email: cnguyen115@gmail.com

Name: Kevin Cheng
Email: kevincheng99@csu.fullerton.edu

Programming Language
====================
C++

Execution of Our Program
========================
1. Compilation: make
2. Execution:
   ./cipher <CIPHER NAME> <KEY> <ENC/DEC> <INPUT FILE> <OUTPUT FILE>
3. For RSA, generate a pair of public or private key. Please see the Notes for
   more details.

Extra Credit
============
Not Implemented.

Notes
=====
Chris and I contribute our works to our Git Repository. Please visit out GitHub
providede below at your convenience. Thank you.
https://github.com/kevincheng99/block-cipher.git

RSA
===
The public and private key are assumed to be 2048 bits. We can use OpenSSL to
generate a pair of public and private key. The command are given as following
from Professor Mikhail Gofman.

  openssl genrsa -out privkey.pem 2048
  openssl rsa -in privkey.pem -outform PEM -pubout -out pubkey.pem

Example to run the RSA encryption by the public key, pubkey.pem
  ./cipher RSA pubkey.pem ENC plaintext.txt ciphertext.txt

Example to run the RSA decryption by the private key, privkey.pem
  ./cipher RSA privkey.pem DEC ciphertext.txt decrypted_ciphertext.txt

By far, we have only implemented the RSA encryption by the public key and RSA
decryption by the private key. For the future improvement, we can implement the
RSA encryption by the public key and RSA decryption by the private key.
