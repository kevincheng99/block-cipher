#ifndef __CIPHER_INTERFACE__
#define __CIPHER_INTERFACE__

#include <string> /* For C++ strings */

using namespace std;

/**
 * This class implements the interface for a cipher.
 * It defines functions usually used in a cipher
 */
class CipherInterface
{
	/** The public members **/
	public:

		/**
		 * The default constructor
		 */
		CipherInterface(){}
		
		/**
		 * Sets the key to use
		 * @param key - the key to use
		 * @return - True if the key is valid and False otherwise
		 */
		virtual bool setKey(const string& key){ return false;  }

    /**
     * Sets the RSA key to use
     * The RSA key can be either the puclic key or private key in PEM format.
     *
     * @param key_file - the key file
     * @param is_public_key - True if the given key file contains the public key
     * in PEM forma. False if the given file contains the private key in PEM
     * format.
     * @return - True if the key is successfully read or False, otherwise.
     */
		virtual bool setKey(const string& key_file, bool is_public_key){ return false;  }

		/**	
		 * Encrypts a plaintext string
		 * @param plaintext - the plaintext string
		 * @return - the encrypted ciphertext string
		 */
		virtual string encrypt(const string& plaintext){ return ""; }

		/**
		 * Decrypts a string of ciphertext
		 * @param ciphertext - the ciphertext
		 * @return - the plaintext
		 */
		virtual string decrypt(const string& ciphertext) { return ""; }

		/* The protected members */
	protected:
	
};

#endif
