
#ifndef RSA_H
#define RSA_H

#include <cstdio>
#include <cstdlib>
#include <string.h>
#include <cctype>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include "CipherInterface.h"
#include <string>
#include <iostream>

using namespace std;

/** 
 * Implements an RSA cipher
 */
class RSA_433: public CipherInterface
{

  /* The public members */
 public:
  //static const unsigned int bit_key_length;

  /**
   * The default constructor
   */
  RSA_433();

  /**
   * Sets the key to use
   * @param key - the key to use
   * @return - True if the key is valid and False otherwise
   */
  virtual bool setKey(const string& key);

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
  virtual bool setKey(const string& key_file, bool is_public_key);

  /**	
   * Encrypts a plaintext string
   * @param plaintext - the plaintext string
   * @return - the encrypted ciphertext string
   */
  virtual string encrypt(const string& plaintext);

  /**
   * Decrypts a string of ciphertext
   * @param ciphertext - the ciphertext
   * @return - the plaintext
   */
  virtual string decrypt(const string& ciphertext);


  /* The protected members */
  protected:
    RSA* pem_key;

};


#endif
