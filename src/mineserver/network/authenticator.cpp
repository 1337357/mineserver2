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
#include "authenticator.h"

Mineserver::Authenticator::Authenticator() {

  std::cout << "About to generate 1024bit RSA key pair." << std::endl;
  if ((rsaKeyPair = RSA_generate_key(1024, 17, 0, 0)) == NULL) {
    std::cerr << "Key pair generation failed" << std::endl;
    exit(1);
  }

  /*Format the public key*/
  certificate = X509_new();
  pk = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pk, rsaKeyPair);
  X509_set_version(certificate, 0);
  X509_set_pubkey(certificate, pk);

  int len;
  unsigned char *buf;
  buf = NULL;
  len = i2d_X509(certificate, &buf);

  //Glue + jesus tape, dont ask - Fador
  publicKey = std::string((char *) (buf + 28), len - 36);
  OPENSSL_free(buf);
}

Mineserver::Authenticator::~Authenticator() {
  
}

void Mineserver::Authenticator::generateId() {
  const std::string temp_nums = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890=-";
  const std::string temp_hex = "0123456789abcdef";

  for (int i = 0; i < 4; i++) {
    encryptionBytes += (char) (temp_nums[rand() % temp_nums.size()]);
  }
  
  //TODO - minecraft.net authentication.
  /* for 'online' mode servers.
  for (int i = 0; i < 16; i++) {
    serverID += (char) (temp_hex[rand() % temp_hex.size()]);
  }
   */
  if (true) {
    serverID = "-";
  }
}

