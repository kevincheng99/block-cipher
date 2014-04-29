#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <vector>
#include <string>
#include <boost/test/unit_test.hpp>
#include <boost/test/test_tools.hpp>
#include "CipherInterface.h"
#include "RSA.h"
#include "DES.h"

using namespace std;

BOOST_AUTO_TEST_CASE(test_decryption1) {
  // initialize the DES cipher object
  DES mydes;

  // set encryption and decryption key
  mydes.setKey("0123456789abcdef");

  // set plaintext
  string plaintext = "12345678";

  // DES encryption
  string ciphertext = mydes.encrypt(plaintext);

  // DES decryption
  string decrypted_ciphertext = mydes.decrypt(ciphertext);

  // check if the decrypted ciphertext is the same as plaintext
  BOOST_CHECK_EQUAL(decrypted_ciphertext, plaintext);

  // print info
  cout << "decrypted ciphertext: " << decrypted_ciphertext << endl;
  cout << "decrypted ciphertext length: " << decrypted_ciphertext.length();
  cout << endl;
}

BOOST_AUTO_TEST_CASE(test_decryption2) {
  // initialize the DES cipher object
  DES mydes;

  // set encryption and decryption key
  mydes.setKey("0123456789abcdef");

  // set plaintext
  string plaintext = "gofman00";

  // DES encryption
  string ciphertext = mydes.encrypt(plaintext);

  // DES decryption
  string decrypted_ciphertext = mydes.decrypt(ciphertext);

  // check if the decrypted ciphertext is the same as plaintext
  BOOST_CHECK_EQUAL(decrypted_ciphertext, plaintext);

  // print info
  cout << "decrypted ciphertext: " << decrypted_ciphertext << endl;
  cout << "decrypted ciphertext length: " << decrypted_ciphertext.length();
  cout << endl;
}

BOOST_AUTO_TEST_CASE(test_decryption3) {
  // initialize the DES cipher object
  DES mydes;

  // set encryption and decryption key
  mydes.setKey("0123456789abcdef");

  // set plaintext
  string plaintext = "hello world, this is kevin!";

  // DES encryption
  string ciphertext = mydes.encrypt(plaintext);

  // DES decryption
  string decrypted_ciphertext = mydes.decrypt(ciphertext);

  // check if the decrypted ciphertext is the same as plaintext
  BOOST_CHECK(decrypted_ciphertext.compare(plaintext) != 0);

  // print info
  cout << "decrypted ciphertext: " << decrypted_ciphertext << endl;
  cout << "decrypted ciphertext length: " << decrypted_ciphertext.length();
  cout << endl;
}
