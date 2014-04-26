all:	cipher RSA_specific

cipher:	cipher.o Playfair.o DES.o RSA.o
	g++ cipher.o Playfair.o DES.o -o cipher -lcrypto

RSA_specific:	RSA_specific.o
	g++ RSA_specific.o -o RSA_specific -lcrypto


cipher.o:	cipher.cpp
	g++ -g -c cipher.cpp 

DES.o:	DES.cpp DES.h
	g++ -g -c DES.cpp

RSA.o:	RSA.cpp RSA.h
	g++ -g -c RSA.cpp


RSA_specific.o:	RSA_specific.cpp
	g++ -g -c RSA_specific.cpp


Playfair.o:	Playfair.cpp Playfair.h CipherInterface.h
	g++ -g -c Playfair.cpp

# Uncomment this code once you add the appropriate files
#RowTransposition.o:	RowTransposition.cpp RowTransposition.h
#	g++ -g -c RowTransposition.cpp


clean:
	rm -rf *.o cipher RSA_specific
