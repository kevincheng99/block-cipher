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
0. For RSA, generate a pair of public or private key. Please see the Notes for
   more details.
1. Compilation: make
2. Execution:
./cipher <CIPHER NAME> <KEY> <ENC/DEC> <INPUT FILE> <OUTPUT FILE>


Extra Credit
============
Not Implemented.

Notes
=====
Chris and I contribute our works to our Git Repository. Please visit out GitHub
providede below at your convenience. Thank you.
https://github.com/kevincheng99/block-cipher.git

For RSA, the public and private key are assumed to be 2048 bits. We can use
OpenSSL to generate a pair of public and private key. The command are given
as following from Professor Mikhail Gofman.

  openssl genrsa -out privkey.pem 2048
  openssl rsa -in privkey.pem -outform PEM -pubout -out pubkey.pem
