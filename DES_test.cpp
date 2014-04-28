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

BOOST_AUTO_TEST_CASE(test_substring) {
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

  //cout << decrypted_ciphertext << endl;
}

