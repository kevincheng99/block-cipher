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
#include "RSA.h"
#include "CipherInterface.h"
//#include <algorithm>
//#include <utility>

using namespace std;

BOOST_AUTO_TEST_CASE(test_setKey1) {
  /**
   * test the incorrect input file
   */

  // initialize the cipher interface to RSA
  CipherInterface* myrsa = new RSA_433();

  // key initialization
  bool is_public_key = true;
  string mykey = "no such key";

  // result of setting RSA key
  bool result = myrsa -> setKey(mykey, is_public_key);

  // boost check if the result is the same as our expectation
  BOOST_CHECK_EQUAL(result, false);
}

BOOST_AUTO_TEST_CASE(test_setKey2) {
  /**
   * test to read a correct public key in the PEM format
   */

  // initialize the cipher interface to RSA
  CipherInterface* myrsa = new RSA_433();

  // key initialization
  bool is_public_key = true;
  string mykey = "pubkey.pem";

  // result of setting RSA key
  bool result = myrsa -> setKey(mykey, is_public_key);

  // boost check if the result is the same as our expectation
  BOOST_CHECK_EQUAL(result, true);
}

BOOST_AUTO_TEST_CASE(test_setKey3) {
  /**
   * test to read a correct private key in the PEM format
   */

  // initialize the cipher interface to RSA
  CipherInterface* myrsa = new RSA_433();

  // key initialization
  bool is_public_key = false;
  string mykey = "privkey.pem";

  // result of setting RSA key
  bool result = myrsa -> setKey(mykey, is_public_key);

  // boost check if the result is the same as our expectation
  BOOST_CHECK_EQUAL(result, true);
}

BOOST_AUTO_TEST_CASE(test_setKey4) {
  /**
   * test to read an incorrect public key in the PEM format
   */

  // create a fake public key
  system("cp pubkey.pem pubkey.pem.sav");
  system("echo 'abc' > pubkey.pem");

  // initialize the cipher interface to RSA
  CipherInterface* myrsa = new RSA_433();

  // key initialization
  bool is_public_key = true;
  string mykey = "pubkey.pem";

  // result of setting RSA key
  bool result = myrsa -> setKey(mykey, is_public_key);

  // boost check if the result is the same as our expectation
  BOOST_CHECK_EQUAL(result, false);

  // restore public key
  system("mv pubkey.pem.sav pubkey.pem");
}

BOOST_AUTO_TEST_CASE(test_setKey5) {
  /**
   * test to read an incorrect private key in the PEM format
   */

  // create a fake private key
  system("cp privkey.pem privkey.pem.sav");
  system("echo 'abc' > privkey.pem");

  // initialize the cipher interface to RSA
  CipherInterface* myrsa = new RSA_433();

  // key initialization
  bool is_public_key = false;
  string mykey = "privkey.pem";

  // result of setting RSA key
  bool result = myrsa -> setKey(mykey, is_public_key);

  // boost check if the result is the same as our expectation
  BOOST_CHECK_EQUAL(result, false);

  // restore private key
  system("mv privkey.pem.sav privkey.pem");
}

BOOST_AUTO_TEST_CASE(test_keylength) {
  /**
   * test the key length
   */

  // initialize RSA
  RSA_433 myrsa;

  // check the key length
  BOOST_CHECK_EQUAL(myrsa.bit_key_length, 2048);
}

BOOST_AUTO_TEST_CASE(test_encrypt1) {
  /**
   * test of RSA encryption by a public key in the PEM format
   */

  // initialize the cipher interface to RSA
  CipherInterface* myrsa = new RSA_433();

  // set key
  bool is_public_key = true;
  myrsa -> setKey("pubkey.pem", is_public_key);

  // encrytion by the public key
  string plaintext("kevin");
  string ciphertext = myrsa -> encrypt(plaintext);

  // print the ciphertext and its length
  cerr << "plaintext: " << plaintext << endl;
  cerr << "ciphertext: " << endl << ciphertext << endl;
  cerr << "ciphertext length: " << ciphertext.length() << endl;
}

BOOST_AUTO_TEST_CASE(test_encrypt2) {
  /**
   * test of RSA encryption: empty plaintext
   */

  // initialize the cipher interface to RSA
  CipherInterface* myrsa = new RSA_433();

  // set key
  bool is_public_key = true;
  myrsa -> setKey("pubkey.pem", is_public_key);

  // encrytion by the public key
  string plaintext("");
  string ciphertext = myrsa -> encrypt(plaintext);

  // check if the ciphertext is expected
  BOOST_CHECK_EQUAL(ciphertext, "");
}

BOOST_AUTO_TEST_CASE(test_encrypt3) {
  /**
   * test of RSA encryption: plaintext length > key length in bytes
   */

  // initialize the cipher interface to RSA
  CipherInterface* myrsa = new RSA_433();

  // set key
  bool is_public_key = true;
  myrsa -> setKey("pubkey.pem", is_public_key);

  // encrytion by the public key
  string plaintext(300, 'k');
  string ciphertext = myrsa -> encrypt(plaintext);

  // check if the ciphertext is expected
  BOOST_CHECK_EQUAL(ciphertext, "");
}

BOOST_AUTO_TEST_CASE(test_decrypt1) {
  /**
   * test of RSA decryption
   *  encrypt the plaintext
   *  decrypt the ciphertext
   */

  // initialize the cipher interface to RSA
  CipherInterface* myrsa = new RSA_433();

  // set the public key
  bool is_public_key = true;
  myrsa -> setKey("pubkey.pem", is_public_key);

  // encrytion by the public key
  string plaintext("Unfortunately I couldn’t run (snr.tar.gz) included in the link that you emailed me");
  string ciphertext = myrsa -> encrypt(plaintext);

  // set the private key
  is_public_key = false;
  myrsa -> setKey("privkey.pem", is_public_key);

  // decrypt the ciphertext
  string decrypted_ciphertext = myrsa -> decrypt(ciphertext);

  // check if the decryption works
  BOOST_CHECK_EQUAL(decrypted_ciphertext, plaintext);

  //cerr << "decrypted_ciphertext: " << decrypted_ciphertext << endl;
  //cerr << "plaintext           : " << plaintext << endl;
}
 
BOOST_AUTO_TEST_CASE(test_decrypt2) {
  /**
   * test of RSA decryption: empty ciphertext
   */

  // initialize the cipher interface to RSA
  CipherInterface* myrsa = new RSA_433();

  // set the private key
  bool is_public_key = false;
  myrsa -> setKey("privkey.pem", is_public_key);

  // decrypt the ciphertext
  string ciphertext = "";
  string decrypted_ciphertext = myrsa -> decrypt(ciphertext);

  // check if the decryption works
  BOOST_CHECK_EQUAL(decrypted_ciphertext, "");
}

BOOST_AUTO_TEST_CASE(test_decrypt3) {
  /**
   * test of RSA decryption: oversize ciphertext
   */

  // initialize the cipher interface to RSA
  CipherInterface* myrsa = new RSA_433();
  // set the private key
  bool is_public_key = false;
  myrsa -> setKey("privkey.pem", is_public_key);

  // decrypt the ciphertext
  string ciphertext(300, 'k');
  string decrypted_ciphertext = myrsa -> decrypt(ciphertext);

  // check if the decryption works
  BOOST_CHECK_EQUAL(decrypted_ciphertext, "");
}


