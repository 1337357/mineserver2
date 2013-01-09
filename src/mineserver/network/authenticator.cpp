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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include <mineserver/network/authenticator.h>

Mineserver::Authenticator::Authenticator() {
  SSL_load_error_strings();

  std::cout << "Generating 1024bit RSA key pair." << std::endl;
  //initilize the pseudo-random number generator.
  srand(time(NULL));
  if((m_rsa = RSA_generate_key(1024, 17, NULL, NULL)) == NULL)
  {
    std::cout << "Key generation failed" << std::endl;
    ERR_print_errors_fp(stdout);
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
  std::cout << "Length of OpenSSL public key: " << len << std::endl;
  for(int i = 0; i < len; i++){
    printf("%x:", (int)buf[i]);
  }
  m_publicKeyLength = len;
  m_publicKey = (uint8_t*)buf;
}

Mineserver::Authenticator::~Authenticator()
{
  X509_free(m_x509);
}

uint8_t* Mineserver::Authenticator::getPublicKey()
{
  return m_publicKey;
}

int16_t Mineserver::Authenticator::getPublicKeyLength()
{
  return m_publicKeyLength;
}

void Mineserver::Authenticator::generateId()
{
  //Need complete do for online mod
}



