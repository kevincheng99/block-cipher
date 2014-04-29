#include "DES.h"

#define ENC 1
#define DEC 0

#include <iostream>

/**
 * Sets the key to use
 * @param key - the key to use
 * @return - True if the key is valid and False otherwise
 */
bool DES::setKey(const string& key)
{
	/**
	 * First let's covert the char string
	 * into an integer byte string
	 */
	
	/* Get the pointer to the cstring */
	const char* cstrKey = key.c_str();
	
	/* The key error code */
	int keyErrorCode = -1;
		
	/* Check for a valid key length */
	if(key.length() / 2 != 8)
	{
		fprintf(stderr, "Invalid key length\n");
		return false;
	}

	/* A single byte */
	unsigned char singleByte = 0;	
	
	/* The key index */
	int keyIndex = 0;
	
	/* The DES key index */
	int desKeyIndex = 0;
		
	/* Go through the entire key character by character */
	while(desKeyIndex != 8)
	{
		/* Convert the key if the character is valid */
		if((this->des_key[desKeyIndex] = twoCharToHexByte(cstrKey + keyIndex)) == 'z')
			return false;
		
		/* Go to the second pair of characters */
		keyIndex += 2;	
		
		/* Increment the index */
		++desKeyIndex;
	}
	
	fprintf(stdout, "DES KEY: ");
	
	/* Print the key */
	for(keyIndex = 0; keyIndex < 8; ++keyIndex)
		fprintf(stdout, "%x", this->des_key[keyIndex]);
	
	fprintf(stdout, "\n");	
	
	
	/* Set the encryption key */
	if ((keyErrorCode = des_set_key_checked(&des_key, this->key)) != 0)
	{
		fprintf(stderr, "\nkey error %d\n", keyErrorCode);
		
		return false;
	}
	
	/* All is well */	
	return true;
}

/**	
 * Encrypts a plaintext string
 * @param plaintext - the plaintext string
 * @return - the encrypted ciphertext string
 */
string DES::encrypt(const string& plaintext)
{
	//LOGIC:
	//1. Check to make sure that the block is exactly 8 characters (i.e. 64 bits)
	//2. Declare an array DES_LONG block[2];
	//3. Use ctol() to convert the first 4 chars into long; store the result in block[0]
	//4. Use ctol() to convert the second 4 chars into long; store the resul in block[1]
	//5. Perform des_encrypt1 in order to encrypt the block using this->key (see sample codes for details)
	//6. Convert the first ciphertext long to 4 characters using ltoc()
	//7. Convert the second ciphertext long to 4 characters using ltoc()
	//8. Save the results in the resulting 8-byte string (e.g. bytes[8])
	//9. Convert the string (e.g. bytes[8]) to a C++ string.
	//10.Return the C++ string
	
	string ptext = plaintext;
	
  size_t number_of_padding = 0;

	while (ptext.size() < 8)
	{
		ptext.append("0");
    number_of_padding++;
	}
	
  // convert int to a character in ASCII
  char number_of_padding_char = '0' + number_of_padding;
  
  /**
   * put the number of padding at the end of padded plaintext block
   * pad only one zero may be a special case?
   * std::string.back() should not be used on the empty string
   * it's important to do the bound checking when dealing with end of string
   * we will remove the padding in the cipher.cpp
   */
  if (number_of_padding > 0 && number_of_padding < 8) {
    size_t last_index = ptext.length() - 1;
    ptext.at(last_index) = number_of_padding_char;
  }


	DES_LONG block[2];
	
	//Convert C++ string to c-string
	char cstr1[4];
	char cstr2[4];

	ptext.copy(cstr1, 4, 0);
	cstr1[4] = '\0';

	ptext.copy(cstr2, 4, 4);
	cstr2[4] = '\0';

	unsigned char ucstr1[4];
	memset(ucstr1, 0, sizeof(ucstr1));

	for (int i = 0; i < sizeof(cstr1); i++) {
	ucstr1[i] = cstr1[i];
	}
	ucstr1[sizeof(cstr1)] = '\0';

	unsigned char ucstr2[4];
	memset(ucstr2, 0, sizeof(ucstr2));

	for (int i = 0; i < sizeof(cstr2); i++) {
	ucstr2[i] = cstr2[i];
	}
	ucstr2[sizeof(cstr2)] = '\0';
  

	//Convert first 4 chars into Long Int
	block[0] = ctol(ucstr1);
	block[1] = ctol(ucstr2);
	
	//Encrypt
	des_encrypt1(block,key,ENC);
	
	
	//Convert long to c string
	unsigned char txtText1[4];
	unsigned char txtText2[4];
	
	ltoc(block[0], txtText1);
	ltoc(block[1], txtText2);
	
	//Convert c string to C++ string
	string convertcstr1 = "";
	for (int i = 0; i < sizeof(txtText1); i++) {
	convertcstr1.push_back(txtText1[i]); 
	}

	string convertcstr2 = "";
	for (int i = 0; i < sizeof(txtText2); i++) {
	convertcstr2.push_back(txtText2[i]); 
	}

  //cout << "ciphertext: " << convertcstr1 + convertcstr2 << endl;
	
	//cout << "decrypt test: " << decrypt(convertcstr1 + convertcstr2) << "|" << endl;
	
	return convertcstr1 + convertcstr2;
}

/**
 * Decrypts a string of ciphertext
 * @param ciphertext - the ciphertext
 * @return - the plaintext
 */
string DES::decrypt(const string& ciphertext)
{
	//LOGIC:
	// Same logic as encrypt(), except in step 5. decrypt instead of encrypting
	
	DES_LONG block[2];
	
	//Convert C++ string to c-string
	/*const char* cstrText1 = ciphertext.substr(0,4).c_str();
	const char* cstrText2 = ciphertext.substr(4,4).c_str();
	
	char cstr1[4], cstr2[4];
	strncpy (cstr1, cstrText1, sizeof(cstrText1));
	strncpy (cstr2, cstrText2, sizeof(cstrText2));
	*/
	
	char cstr1[4];
	char cstr2[4];

	ciphertext.copy(cstr1, 4, 0);
	cstr1[4] = '\0';

	ciphertext.copy(cstr2, 4, 4);
	cstr2[4] = '\0';
	
	unsigned char ucstr1[4];
	memset(ucstr1, 0, sizeof(ucstr1));

	for (int i = 0; i < sizeof(cstr1); i++) {
	ucstr1[i] = cstr1[i];
	}
	ucstr1[sizeof(cstr1)] = '\0';

	unsigned char ucstr2[4];
	memset(ucstr2, 0, sizeof(ucstr2));

	for (int i = 0; i < sizeof(cstr2); i++) {
	ucstr2[i] = cstr2[i];
	}
	ucstr2[sizeof(cstr2)] = '\0';
	
	//Convert first 4 chars into Long Int
	block[0] = ctol(ucstr1);
	block[1] = ctol(ucstr2);
	
	//Decrypt
	des_encrypt1(block,key,DEC);
	
	//Convert Long back to c string
	unsigned char txtText1[4];
	unsigned char txtText2[4];
	
	ltoc(block[0], txtText1);
	ltoc(block[1], txtText2);
	
	//Convert c string to C++ string
	string convertcstr1 = "";
	for (int i = 0; i < sizeof(txtText1); i++) {
	convertcstr1.push_back(txtText1[i]); 
	}

	string convertcstr2 = "";
	for (int i = 0; i < sizeof(txtText2); i++) {
	convertcstr2.push_back(txtText2[i]); 
	}
	
	//cout << "length of plaintext: " << test.length() << endl;
	
	return convertcstr1 + convertcstr2;
}

/**
 * Converts an array of 8 characters
 * (i.e. 4 bytes/32 bits)
 * @param c - the array of 4 characters (i.e. 1-byte per/character
 * @return - the long integer (32 bits) where each byte
 * is equivalent to one of the bytes in a character array
 */
DES_LONG DES::ctol(unsigned char *c) 
{
        /* The long integer */
	DES_LONG l;
        
	l =((DES_LONG)(*((c)++)));
        l = l | (((DES_LONG)(*((c)++)))<<8L);
        l = l | (((DES_LONG)(*((c)++)))<<16L);
        l = l | (((DES_LONG)(*((c)++)))<<24L);
        return l;
};


/** 
 * Converts a long integer (4 bytes = 32 bits)
 * into an array of 8 characters.
 * @param l - the long integer to convert
 * @param c - the character array to store the result
 */
void DES::ltoc(DES_LONG l, unsigned char *c) 
{
        *((c)++)=(unsigned char)(l&0xff);
        *((c)++)=(unsigned char)(((l)>> 8L)&0xff);
        *((c)++)=(unsigned char)(((l)>>16L)&0xff);
        *((c)++)=(unsigned char)(((l)>>24L)&0xff);
}

/**
 * Converts a character into a hexidecimal integer
 * @param character - the character to convert
 * @return - the converted character, or 'z' on error
 */
unsigned char DES::charToHex(const char& character)
{
	/* Is the first digit 0-9 ? */	
	if(character >= '0' && character <= '9')	
		/* Convert the character to hex */
		return character - '0';
	/* It the first digit a letter 'a' - 'f'? */
	else if(character >= 'a' && character <= 'f')
		/* Conver the cgaracter to hex */
		return (character - 97) + 10;	
	/* Invalid character */
	else return 'z';
}

/**
 * Converts two characters into a hex integers
 * and then inserts the integers into the higher
 * and lower bits of the byte
 * @param twoChars - two charcters representing the
 * the hexidecimal nibbles of the byte.
 * @param twoChars - the two characters
 * @return - the byte containing having the
 * valud of two characters e.g. string "ab"
 * becomes hexidecimal integer 0xab.
 */
unsigned char DES::twoCharToHexByte(const char* twoChars)
{
	/* The byte */
	unsigned char singleByte;
	
	/* The second character */
	unsigned char secondChar;

	/* Convert the first character */
	if((singleByte = charToHex(twoChars[0])) == 'z') 
	{
		/* Invalid digit */
		return 'z';
	}
	
	/* Move the newly inserted nibble from the
	 * lower to upper nibble.
	 */
	singleByte = (singleByte << 4);
	
	/* Conver the second character */
	if((secondChar = charToHex(twoChars[1])) == 'z')
		return 'z'; 
	
	/* Insert the second value into the lower nibble */	
	singleByte |= secondChar;

	return singleByte;
}


