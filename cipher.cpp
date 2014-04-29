#include <cstdio>
#include <cstring>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "CipherInterface.h"
#include "Playfair.h"
#include "DES.h"
#include "RSA.h"

using namespace std;

int main(int argc, char** argv)
{
  /** 
   * Professor Gofman's comment block
   * REPLACE THIS PART WITH YOUR CODE 
   * THE CODE BELOW IS A SAMPLE TO 
   * ILLUSTRATE INSTANTIATION OF CLASSES
   * THAT USE THE SAME INTERFACE.
   */	

  // to represent each field from the command line
  enum CommandLineFieldName {
    kCipherName = 1,
    kKey = 2,
    kEncryptionOrDecryption = 3,
    kInputFile = 4,
    kOutputFile = 5,
  };

  // check the command line argument
  if (argc != 6) {
    cerr << "ERROR: ./cipher <CIPHER NAME> <KEY> <ENC/DEC> <INPUT FILE> <OUTPUT FILE>" << endl;
    return -1;
  }

  /**
   * read input files
   */

  // a pointer to the cipher interface
  CipherInterface* cipher = NULL;

  // choose a cipher
  if (strcmp("DES", argv[kCipherName]) == 0) {
    cipher = new DES();
  }
  else if (strcmp("RSA", argv[kCipherName]) == 0) {
    cipher = new RSA_433();
  }
  else {
    cerr << "invalid cipher name: " << argv[kCipherName] << endl;
    return -4; 
  }

  // Error checks
  if(!cipher)
  {
    fprintf(stderr, "ERROR [%s %s %d]: could not allocate memory\n",	
            __FILE__, __FUNCTION__, __LINE__);
    exit(-1);
  }

  /**
   * the following code blocks of encryption and decryption by DES or RAS will
   * be merged with classical ciphers or the stage of choosing a cipher above.
   */

  // DES encryption or decryption
  //if (strcmp("DES", argv[kCipherName]) == 0) {
    /* Set the encryption key
     * A valid key comprises 16 hexidecimal
     * characters. Below is one example.
     * Your program should take input from
     * command line.
     */
 //   cipher->setKey("0123456789abcdef");

    /* Perform encryption */
    //string cipherText = cipher->encrypt("hello world");

    /* Perform decryption */
    //cipher->decrypt(cipherText);	
  //}

  
  // DES encryption or decryption
  if (strcmp("DES", argv[kCipherName]) == 0) {
    if (strcmp("ENC", argv[kEncryptionOrDecryption]) == 0) {
      // initialize input file stream object
      ifstream input_file(argv[kInputFile], ifstream::in);

      // check the connection
      if (!input_file) {
        perror("open input file");
        return -2;
      }

      // initialize the string object to hold plaintext
      string plaintext = "";

      // read the plaintext
      while (input_file.good()) {
        char next_character = input_file.get();
        plaintext.push_back(next_character);
      }
      plaintext.erase(plaintext.length() - 1);

      // close input file
      input_file.close();

      // print the plaintext
      // cout << plaintext;
      // cout << plaintext.length() << endl;

      // set the encryption key
      //bool is_public_key = true;
      //string public_key(argv[kKey]);
      string key(argv[kKey]);

      //if (!cipher -> setKey(public_key, is_public_key)) {
      if (!cipher -> setKey(key)) {
        cerr << "invalid key" << endl;
        return -5;
      }

      // get the max plaintext block size
      size_t maximum_block_size = 8;

      // get the number of plaintext blocks
      size_t number_of_blocks = -1;

      if ((plaintext.length() % maximum_block_size) == 0) {
        number_of_blocks = plaintext.length() / maximum_block_size;
      }
      else {
        number_of_blocks = plaintext.length() / maximum_block_size + 1;
      }

      //cout << number_of_blocks << endl;

      // encrypt the plaintext block by block
      string ciphertext = "";

      for (size_t i = 0 ; i < number_of_blocks; ++i) {
        // get the beginning of plaintext block
        size_t start_position = i * maximum_block_size;

        // get the block of plaintext
        string block = plaintext.substr(start_position, maximum_block_size);

        // encrypt the block
        ciphertext += cipher -> encrypt(block);
      }

      // initialize output stream object
      ofstream output_file(argv[kOutputFile], ofstream::out);

      // check the output file
      if (!output_file) {
        perror("open output file");
        return -3;
      }

      // save the ciphertext to the output file
      output_file << ciphertext;
    }
    else if (strcmp("DEC", argv[kEncryptionOrDecryption]) == 0) {
      // initialize input file stream object
      ifstream input_file(argv[kInputFile], ifstream::in);

      // check the connection
      if (!input_file) {
        perror("open input file");
        return -2;
      }

      // initialize the string object to hold ciphertext
      string ciphertext = "";

      // read the plaintext
      while (input_file.good()) {
        char next_character = input_file.get();
        ciphertext.push_back(next_character);
      }
      ciphertext.erase(ciphertext.length() - 1);

      // close input file
      input_file.close();

      // set the private key
      //bool is_public_key = false;
      //string private_key(argv[kKey]);

      string key(argv[kKey]);
      if (!cipher -> setKey(key)) {
        cerr << "invalid key" << endl;
        return -5;
      }

      // get the maximum size of ciphertext block
      size_t ciphertext_block_size = 8;

      // get the number of ciphertext blocks
      size_t number_of_blocks = -1;

      if ((ciphertext.length() % ciphertext_block_size)  == 0) {
        number_of_blocks = ciphertext.length() / ciphertext_block_size;
      }
      else {
        cerr << "Decryption Error: Possibly an padding error during the RSA encryption" << endl;
        return -7;
      }

      // decryption by the private key
      string decrypted_ciphertext = "";

      for (size_t i = 0; i < number_of_blocks; ++i) {
        // get the beginning of ciphertext block
        size_t start_position = i * ciphertext_block_size;

        // get the ciphertext block
        string block = ciphertext.substr(start_position, ciphertext_block_size);

        // decrypte by the private key
        decrypted_ciphertext += cipher -> decrypt(block);
      }

      //cout << decrypted_ciphertext;
      //cout << decrypted_ciphertext.length() << endl;

      // initialize output stream object
      ofstream output_file(argv[kOutputFile], ofstream::out);

      // check the output file
      if (!output_file) {
        perror("open output file");
        return -3;
      }

      // save the ciphertext to the output file
      output_file << decrypted_ciphertext;
    }
    else {
      cerr << "invalid ENC/DEC option: " << argv[kEncryptionOrDecryption];
      cerr << endl;

      // close output file stream object
      //output_file.close();

      return -6;
    }
  }


  // RAS encryption or decryption
  if (strcmp("RSA", argv[kCipherName]) == 0) {
    if (strcmp("ENC", argv[kEncryptionOrDecryption]) == 0) {
      // initialize input file stream object
      ifstream input_file(argv[kInputFile], ifstream::in);

      // check the connection
      if (!input_file) {
        perror("open input file");
        return -2;
      }

      // initialize the string object to hold plaintext
      string plaintext = "";

      // read the plaintext
      while (input_file.good()) {
        char next_character = input_file.get();
        plaintext.push_back(next_character);
      }
      plaintext.erase(plaintext.length() - 1);

      // close input file
      input_file.close();

      // print the plaintext
      // cout << plaintext;
      // cout << plaintext.length() << endl;

      // set the encryption key
      bool is_public_key = true;
      string public_key(argv[kKey]);

      if (!cipher -> setKey(public_key, is_public_key)) {
        cerr << "invalid key" << endl;
        return -5;
      }

      // get the max plaintext block size
      size_t maximum_block_size = 214;

      // get the number of plaintext blocks
      size_t number_of_blocks = -1;

      if ((plaintext.length() % maximum_block_size) == 0) {
        number_of_blocks = plaintext.length() / maximum_block_size;
      }
      else {
        number_of_blocks = plaintext.length() / maximum_block_size + 1;
      }

      //cout << number_of_blocks << endl;

      // encrypt the plaintext block by block
      string ciphertext = "";

      for (size_t i = 0 ; i < number_of_blocks; ++i) {
        // get the beginning of plaintext block
        size_t start_position = i * maximum_block_size;

        // get the block of plaintext
        string block = plaintext.substr(start_position, maximum_block_size);

        // encrypt the block
        ciphertext += cipher -> encrypt(block);
      }

      // initialize output stream object
      ofstream output_file(argv[kOutputFile], ofstream::out);

      // check the output file
      if (!output_file) {
        perror("open output file");
        return -3;
      }

      // save the ciphertext to the output file
      output_file << ciphertext;
    }
    else if (strcmp("DEC", argv[kEncryptionOrDecryption]) == 0) {
      // initialize input file stream object
      ifstream input_file(argv[kInputFile], ifstream::in);

      // check the connection
      if (!input_file) {
        perror("open input file");
        return -2;
      }

      // initialize the string object to hold ciphertext
      string ciphertext = "";

      // read the plaintext
      while (input_file.good()) {
        char next_character = input_file.get();
        ciphertext.push_back(next_character);
      }
      ciphertext.erase(ciphertext.length() - 1);

      // close input file
      input_file.close();

      // set the private key
      bool is_public_key = false;
      string private_key(argv[kKey]);

      
      if (!cipher -> setKey(private_key, is_public_key)) {
        cerr << "invalid key" << endl;
        return -5;
      }


      // get the maximum size of ciphertext block
      size_t ciphertext_block_size = 256;

      // get the number of ciphertext blocks
      size_t number_of_blocks = -1;

      if ((ciphertext.length() % ciphertext_block_size)  == 0) {
        number_of_blocks = ciphertext.length() / ciphertext_block_size;
      }
      else {
        cerr << "Decryption Error: Possibly an padding error during the RSA encryption" << endl;
        return -7;
      }

      // decryption by the private key
      string decrypted_ciphertext = "";

      for (size_t i = 0; i < number_of_blocks; ++i) {
        // get the beginning of ciphertext block
        size_t start_position = i * ciphertext_block_size;

        // get the ciphertext block
        string block = ciphertext.substr(start_position, ciphertext_block_size);

        // decrypte by the private key
        decrypted_ciphertext += cipher -> decrypt(block);
      }

      //cout << decrypted_ciphertext;
      //cout << decrypted_ciphertext.length() << endl;

      // initialize output stream object
      ofstream output_file(argv[kOutputFile], ofstream::out);

      // check the output file
      if (!output_file) {
        perror("open output file");
        return -3;
      }

      // save the ciphertext to the output file
      output_file << decrypted_ciphertext;
    }
    else {
      cerr << "invalid ENC/DEC option: " << argv[kEncryptionOrDecryption];
      cerr << endl;

      // close output file stream object
      //output_file.close();

      return -6;
    }
  }

  // close outpout file stream object



  return 0;
}
// print the plaintext
//for (vector<string>::iterator itr = plaintext.begin();
//itr != plaintext.end();
//++itr) {
//cout << *itr << endl;
//}


