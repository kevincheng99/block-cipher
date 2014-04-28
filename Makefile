# Name: Tsu-Hsiang Kevin Cheng
# Class: CPSC433
# Assignment: 2
# Email: kevincheng99@csu.fullerton.edu
# Due Date: April 28, 2014
# 
# DESCRIPTION
#		To better comprehend the block ciphers, we implement two block
#		ciphers, DES and RSA.
#

#all:	cipher RSA_specific 
all:	cipher RSA_specific test_RSA test_DES

cipher:	cipher.o Playfair.o DES.o RSA.o
	g++ cipher.o Playfair.o DES.o RSA.o -o cipher -lcrypto

RSA_specific:	RSA_specific.o
	g++ RSA_specific.o -o RSA_specific -lcrypto

cipher.o: cipher.cpp
	g++ -g -c cipher.cpp 

DES.o:	DES.cpp DES.h CipherInterface.h
	g++ -g -c DES.cpp

RSA.o:	RSA.cpp RSA.h CipherInterface.h
	g++ -g -c RSA.cpp

RSA_specific.o:	RSA_specific.cpp CipherInterface.h
	g++ -g -c RSA_specific.cpp

Playfair.o: Playfair.cpp Playfair.h CipherInterface.h
	g++ -g -c Playfair.cpp

test_RSA: RSA_test.cpp RSA.o CipherInterface.h
	g++ -g -Wall -o test_RSA RSA_test.cpp RSA.o -lboost_unit_test_framework -lcrypto

test_DES: DES_test.cpp DES.o CipherInterface.h
	g++ -g -Wall -o test_DES DES_test.cpp DES.o -lboost_unit_test_framework -lcrypto

# Uncomment this code once you add the appropriate files
#RowTransposition.o:	RowTransposition.cpp RowTransposition.h
#	g++ -g -c RowTransposition.cpp

.PHONY: clean clean_tests
clean:
	rm -rf *.o cipher RSA_specific 

clean_test:
	rm test_RSA test_DES
