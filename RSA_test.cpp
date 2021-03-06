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

//BOOST_AUTO_TEST_CASE(test_keylength) {
/**
 * test the key length
 */

//// initialize RSA
//RSA_433 myrsa;

//// check the key length
//BOOST_CHECK_EQUAL(myrsa.bit_key_length, 2048);
//}

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
  //cerr << "plaintext: " << plaintext << endl;
  //cerr << "ciphertext: " << endl << ciphertext << endl;
  //cerr << "ciphertext length: " << ciphertext.length() << endl;
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

BOOST_AUTO_TEST_CASE(test_encrypt4) {
  /**
   * test of RSA encryption: plaintext length is at its maximum length, which is
   * RSA_size(RSA_key) - 42 from the official OpenSSL documentation, when doing
   * RSA_PKSC1_OAEP_PADDING
   *
   * the error message about the padding error was inaccurate due to BOOST lib?
   */

  // initialize the cipher interface to RSA
  CipherInterface* myrsa = new RSA_433();

  // set key
  bool is_public_key = true;
  myrsa -> setKey("pubkey.pem", is_public_key);

  // encrytion by the public key
  string plaintext(215, 'k');
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

BOOST_AUTO_TEST_CASE(test_decrypt4) {
  /**
   * test of RSA decryption: 214 bytes
   * from the OpenSSL documentation, the plaintext size must be less than
   * RSA_size(RSA_key) - 41 when using RSA_PKSC1_OAEP_PADDING
   * since our key is 256 bytes, then, we should set the maxim size of plaintext
   * as 256 - 42 = 214
   */

  // initialize the cipher interface to RSA
  CipherInterface* myrsa = new RSA_433();

  // set the public key
  bool is_public_key = true;
  myrsa -> setKey("pubkey.pem", is_public_key);

  // encrytion by the public key
  string plaintext(214, 'k');
  string ciphertext = myrsa -> encrypt(plaintext);

  // set the private key
  is_public_key = false;
  myrsa -> setKey("privkey.pem", is_public_key);

  // decrypt the ciphertext
  string decrypted_ciphertext = myrsa -> decrypt(ciphertext);

  // check if the decryption works
  BOOST_CHECK_EQUAL(decrypted_ciphertext, plaintext);
}

BOOST_AUTO_TEST_CASE(test_plaintext_block_size1) {
  /**
   * test of RSA encryption: test padding
   * plaintext block size 1 byte
   */

  // initialize the cipher interface to RSA
  CipherInterface* myrsa = new RSA_433();

  // set public key
  bool is_public_key = true;
  myrsa -> setKey("pubkey.pem", is_public_key);

  // encrytion by the public key
  string plaintext(1, 'k');
  string ciphertext = myrsa -> encrypt(plaintext);

  // set the private key
  is_public_key = false;
  myrsa -> setKey("privkey.pem", is_public_key);

  // decryption by the private key
  string decrypted_ciphertext = myrsa -> decrypt(ciphertext);

  // check the decryption result against the plaintext
  BOOST_CHECK_EQUAL(decrypted_ciphertext, plaintext);
}

BOOST_AUTO_TEST_CASE(test_plaintext_block_size2) {
  /**
   * test of RSA encryption: test padding
   * plaintext block size 100 byte
   */

  // initialize the cipher interface to RSA
  CipherInterface* myrsa = new RSA_433();

  // set public key
  bool is_public_key = true;
  myrsa -> setKey("pubkey.pem", is_public_key);

  // encrytion by the public key
  string plaintext(100, 'k');
  string ciphertext = myrsa -> encrypt(plaintext);

  // set the private key
  is_public_key = false;
  myrsa -> setKey("privkey.pem", is_public_key);

  // decryption by the private key
  string decrypted_ciphertext = myrsa -> decrypt(ciphertext);

  // check the decryption result against the plaintext
  BOOST_CHECK_EQUAL(decrypted_ciphertext, plaintext);
}

BOOST_AUTO_TEST_CASE(test_plaintext_block_size3) {
  /**
   * test of RSA encryption: test padding
   * plaintext block size 214 byte
   * critical point: RSA_size(RSA) - 41: 214 and 215
   */

  // initialize the cipher interface to RSA
  CipherInterface* myrsa = new RSA_433();

  // set public key
  bool is_public_key = true;
  myrsa -> setKey("pubkey.pem", is_public_key);

  // encrytion by the public key
  string plaintext(214, 'k');
  string ciphertext = myrsa -> encrypt(plaintext);

  // set the private key
  is_public_key = false;
  myrsa -> setKey("privkey.pem", is_public_key);

  // decryption by the private key
  string decrypted_ciphertext = myrsa -> decrypt(ciphertext);

  // check the decryption result against the plaintext
  BOOST_CHECK_EQUAL(decrypted_ciphertext, plaintext);
}

BOOST_AUTO_TEST_CASE(test_plaintext_block_size4) {
  /**
   * test of RSA encryption: test padding
   * plaintext block size 215 byte
   * critical point: RSA_size(RSA) - 41: 214 and 215
   */

  // initialize the cipher interface to RSA
  CipherInterface* myrsa = new RSA_433();

  // set public key
  bool is_public_key = true;
  myrsa -> setKey("pubkey.pem", is_public_key);

  // encrytion by the public key
  string plaintext(215, 'k');
  string ciphertext = myrsa -> encrypt(plaintext);

  // set the private key
  is_public_key = false;
  myrsa -> setKey("privkey.pem", is_public_key);

  // decryption by the private key
  string decrypted_ciphertext = myrsa -> decrypt(ciphertext);

  // check the decryption result against the plaintext
  BOOST_CHECK(decrypted_ciphertext.compare(plaintext) != 0);
}

BOOST_AUTO_TEST_CASE(test_plaintext_block_size5) {
  /**
   * test of RSA encryption: test padding
   * plaintext block size 256 byte same as the key size
   */

  // initialize the cipher interface to RSA
  CipherInterface* myrsa = new RSA_433();

  // set public key
  bool is_public_key = true;
  myrsa -> setKey("pubkey.pem", is_public_key);

  // encrytion by the public key
  string plaintext(256, 'k');
  string ciphertext = myrsa -> encrypt(plaintext);

  // set the private key
  is_public_key = false;
  myrsa -> setKey("privkey.pem", is_public_key);

  // decryption by the private key
  string decrypted_ciphertext = myrsa -> decrypt(ciphertext);

  // check the decryption result against the plaintext
  BOOST_CHECK(decrypted_ciphertext.compare(plaintext) != 0);
}

/**
 * result summary
 * from the testing of plaintext block size, due to RSA_PKCS1_OAEP_PADDING, the
 * maximum plaintext block size is 214 bytes. After padding, it is 256 bytes to
 * match the size of public or private key. For decryption with
 * RSA_PKCS1_OAEP_PADDING, the ciphertext of 256 bytes is decrypted and
 * processed to remove the padding.
 */




































