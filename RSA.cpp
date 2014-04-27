/**
 * The algorithms and skeleton codes are provided by Professor Mikhail Gofman. The
 * implmentation is modifed to satisfy the project requirement and our cipher
 * interface.
 *
 * Date: April 26, 2014
 */

#include "RSA.h"

RSA_433::RSA_433(): pem_key(NULL) {
}

const unsigned int RSA_433::bit_key_length = 2048;

/**
 * Sets the key to use.
 *
 * @param key - the key to use
 * @return - True if the key is valid and False otherwise
 */
bool RSA_433::setKey(const std::string& key) {
  return false;
}

/**
 * Sets the key to use.
 * The key in use is expected to be in the Privacy-enhanced Electronic Mail
 * format (PEM). To specify which key to use for either the RSA encryption or
 * RSA decryption solely depends on an user. The specified key is a public key
 * when the user decide it is a RSA encryption. The specified key is a private
 * key when the user decide it is a RSA decryption. This control is done through
 * the cipher interface.
 *
 * @param key_file - the file contains our key in PEM format.
 * @return - True if the key is valid and False otherwise
 */
bool RSA_433::setKey(const std::string& key_file, bool is_public_key) {
  using namespace std;

  // open the PEM file containing our key of interests
  FILE* input_file = fopen(key_file.c_str(), "r");

  // check if input file is open properly
  if (!input_file) {
    perror("fopen");
    return false;
  }

  // read the public/private key in the PEM format
  if (is_public_key) {
    pem_key = PEM_read_RSA_PUBKEY(input_file, NULL, NULL, NULL);

    // check if the public key is read successfully
    if (!pem_key) {
      perror("PEM_read_RSA_PUBKEY");
      return false;
    }
  }
  else{
    pem_key = PEM_read_RSAPrivateKey(input_file, NULL, NULL, NULL);

    // check if the public key is read successfully
    if (!pem_key) {
      perror("PEM_read_RSAPrivateKey");
      return false;
    }
  }

  // close the input file assoicated with the stream and disassociates it
  fclose(input_file);

  return true;
}

/**	
 * Encrypts a plaintext string
 * @param plaintext - the plaintext string
 * @return - the encrypted ciphertext string
 */
std::string RSA_433::encrypt(const std::string& plaintext) {
  using namespace std;

  // check if the plaintext is empty
  if (plaintext.empty()) {
    cerr << "ERROR: plaintext is empty" << endl;
    return "";
  }

  // check if the plaintext is longer than the key size - 42
  // when using the RSA_PKSC1_OAEP_PADDING, the maxium size of plaintext block
  // is RSA_size(key) - 42
  //unsigned int byte_key_length = bit_key_length / 8;
  unsigned int maxim_plaintext_block_size = bit_key_length / 8 - 42;
  if (plaintext.length() > maxim_plaintext_block_size) {
    cerr << "ERROR: plaintext block is longer than the key length" << endl;
    cerr << "plaintext length: " << plaintext.length() << " bytes" << endl;
    cerr << "maximum block size: " << maxim_plaintext_block_size;
    cerr << " bytes" << endl;
    return "";
  }

  /**
   * RSA public key encryption for the plaintext block
   *  int size: plaintext block size in bytes
   *  unsign char* plaintext
   *  unsign char* ciphertext: RSA_size(key) bytes of memory
   *  RSA* public key: PEM format
   *  int padding: RSA_PKCS1_OAEP_PADDING
   */

  // size of plaintext block in bytes
  size_t plaintext_block_size = plaintext.length();

  // initialize a plaintext buffer to hold plaintext data
  char plaintext_buffer[plaintext_block_size];
  memset(plaintext_buffer, 0, sizeof(plaintext_buffer));

  // fill the buffer with plaintext
  plaintext.copy(plaintext_buffer, plaintext_block_size);

  // have a unsigned char pointer to the plaintext buffer
  //unsigned char* uplaintext = (unsigned char*) plaintext_buffer;
  unsigned char* uplaintext =
      reinterpret_cast<unsigned char*>(plaintext_buffer);

  // initialize the ciphertext buffer
  unsigned char uciphertext[bit_key_length];
  memset(uciphertext, 0, sizeof(uciphertext));

  // encrypt the plaintext block
  int size_of_encrypted_data = RSA_public_encrypt(plaintext_block_size,
                                                  uplaintext,
                                                  uciphertext,
                                                  pem_key,
                                                  RSA_PKCS1_OAEP_PADDING);

  // check if the encryption is successful
  if (size_of_encrypted_data < 0) {
    // initialize a error buffer
    char error_buffer[256];
    memset(error_buffer, 0, sizeof(error_buffer));

    // register the error strings for all libcrypto functions
    ERR_load_crypto_strings();

    // get the error string based on the error code
    ERR_error_string(ERR_get_error(), error_buffer);

    // print the error message
    fprintf(stderr, "Encryption Error: %s\n", error_buffer);

    return "";
  }


  // convert ciphertext in c array to a string
  // Note: using reinterpret_cast may not be a safe way
  //string ciphertext_block(reinterpret_cast<char*>(uciphertext));
  
  string ciphertext_block = "";

  for (int i = 0; i < size_of_encrypted_data; i++) {
    ciphertext_block.push_back(uciphertext[i]);
  }

  //cerr << "size of encrypted data: " << size_of_encrypted_data << endl;
  //cerr << "size of ciphertext string: " << ciphertext_block.length() << endl;

  return ciphertext_block;
}

/**
 * Decrypts a string of ciphertext
 * @param ciphertext - the ciphertext
 * @return - the plaintext
 */
std::string RSA_433::decrypt(const std::string& ciphertext) {
  using namespace std;
  
  // check if the ciphertext is empty
  if (ciphertext.empty()) {
    cerr << "ERROR: ciphertext is empty" << endl;
    return "";
  }

  // check if the ciphertext is longer than the key size
  unsigned int byte_key_length = bit_key_length / 8;
  if (ciphertext.length() > byte_key_length) {
    cerr << "ERROR: ciphertext block is longer than the key length" << endl;
    cerr << "ciphertext length: " << ciphertext.length() << " bytes" << endl;
    cerr << "key length: " << byte_key_length << " bytes" << endl;
    return "";
  }

  /**
   * RSA private-key dencryption for the ciphertext block
   *  int size: ciphertext block size in byte
   *  unsign char* ciphertext
   *  unsign char* decrypted_ciphertext: RSA_size(key) bytes of memory
   *  RSA* private key: PEM format
   *  int padding: RSA_PKCS1_OAEP_PADDING
   */

  // size of ciphertext blocks in bytes
  size_t ciphertext_block_size = ciphertext.length();

  // initialize a buffer to hold ciphertext
  char ciphertext_buffer[ciphertext_block_size];
  memset(ciphertext_buffer, 0, sizeof(ciphertext_buffer));

  // fill the buffer with the ciphertext
  ciphertext.copy(ciphertext_buffer, ciphertext_block_size);

  // have a unsigned pointer point to the plaintext buffer
  unsigned char* uciphertext =
      reinterpret_cast<unsigned char*>(ciphertext_buffer);

  // initialize the decrypted ciphertext buffer 
  unsigned char decrypted_ciphertext[bit_key_length];
  memset(decrypted_ciphertext, 0, sizeof(decrypted_ciphertext));

  // decrypt the ciphertext by the private key in the PEM format
  int size_of_decrypted_data = RSA_private_decrypt(ciphertext_block_size,
                                                   uciphertext,
                                                   decrypted_ciphertext,
                                                   pem_key,
                                                   RSA_PKCS1_OAEP_PADDING);
  
  // check if the decryption is successful
  if (size_of_decrypted_data < 0) {
    // initialize a error buffer
    char error_buffer[256];
    memset(error_buffer, 0, sizeof(error_buffer));

    // register the error strings for all libcrypto functions
    ERR_load_crypto_strings();

    // get the error string based on the error code
    ERR_error_string(ERR_get_error(), error_buffer);

    // print the error message
    fprintf(stderr, "Decription Error: %s\n", error_buffer);

    return "";
  }

  //cerr << "size of decrypted data: " << size_of_decrypted_data << endl;

  // convert a c-array to a cpp string
  string plaintext_block(reinterpret_cast<char*>(decrypted_ciphertext));

  return plaintext_block;
}


//for (size_t i = 0; i < sizeof(uplaintext); i++) {
////fprintf(stderr, "%02x", uplaintext[i]);
//fprintf(stderr, "%c", uplaintext[i]);
//}
//fprintf(stderr, "\n");


