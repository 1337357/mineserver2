/*
  Copyright (c) 2011-2013, The Mineserver Project
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 * Neither the name of the The Mineserver Project nor the
    names of its contributors may be used to endorse or promote products
    derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <iostream>
#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <cstring>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include <mineserver/network/authenticator.h>

Mineserver::Network_Authenticator::Network_Authenticator()
{
  SSL_load_error_strings();

  std::cout << "Generating 1024bit RSA key pair." << std::endl;
  //initilize the pseudo-random number generator.
  srand(time(NULL));
  if((m_rsa = RSA_generate_key(1024, 17, NULL, NULL)) == NULL)
  {
    std::cout << "Key generation failed" << std::endl;
    ERR_print_errors_fp(stdout); //TODO - switch to logging class
    exit(1);
  }

  //allocate and initialize a X509 certificate structure
  m_x509 = X509_new();
  m_privateKey = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(m_privateKey, m_rsa);
  X509_set_version(m_x509,0);
  X509_set_pubkey(m_x509, m_privateKey);

  int len;
  unsigned char *buf;
  buf = NULL;
  len = i2d_X509(m_x509, &buf);
  m_publicKeyLength = len;
  m_publicKey = (uint8_t*)buf;
}

Mineserver::Network_Authenticator::~Network_Authenticator()
{
  X509_free(m_x509);
}

uint8_t* Mineserver::Network_Authenticator::getPublicKey()
{
  return m_publicKey;
}

int16_t Mineserver::Network_Authenticator::getPublicKeyLength()
{
  return m_publicKeyLength;
}

void Mineserver::Network_Authenticator::generateId()
{
  //todo - Need complete do for online mode
}

/**
 * Compare the RSA encrypted verification token with the one generated for the
 * Mineserver::Network_Client
 */
bool Mineserver::Network_Authenticator::verifyEncryptionBytes(short encryptedLength, const uint8_t* encryptedBytes, std::vector<uint8_t> token){

  uint8_t * buffer;
  buffer = new uint8_t[token.size()];
  memset(buffer, 0, token.size());

  int resultLength = RSA_private_decrypt(encryptedLength, encryptedBytes, buffer, m_rsa , RSA_PKCS1_PADDING);

  //compare the encrypted and decrypted arrays.
  int difference = memcmp(&token[0], buffer, resultLength);
  if(resultLength == 4 && difference == 0){
    delete[] buffer;
    return true;
  }
  else if(resultLength < 0){
    ERR_print_errors_fp(stdout);
  }
  delete[] buffer;
  return false;


}

uint8_t* Mineserver::Network_Authenticator::decryptSymmetricKey(short length, uint8_t* bytes){
  uint8_t buffer[length];
  memset(buffer, 0, length);
  int resultLength = RSA_private_decrypt(length, bytes, buffer, m_rsa , RSA_PKCS1_PADDING);

  if(resultLength == 16){
    //the result should be 16 bytes in length
    uint8_t* de = new uint8_t[16];
    for(int i = 0; i < 16; i++){
      de[i] = buffer[i];
    }

    return de;
  }

  printf("Result of decrypted symmetric key was: %i\n Something went WRONG!\n", resultLength);
  ERR_print_errors_fp(stdout);
  return NULL;
}


