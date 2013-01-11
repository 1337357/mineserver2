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

#include <string>

#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#ifndef MINESERVER_NETWORK_AUTHENTICATOR_H
#define	MINESERVER_NETWORK_AUTHENTICATOR_H

namespace Mineserver {
   /**
   * Generates keys and server ID information.
   */
  class Network_Authenticator : public boost::enable_shared_from_this<Mineserver::Network_Authenticator>
  {
  private:
    std::string serverId;
    RSA* m_rsa;
    X509* m_x509;
    EVP_PKEY* m_privateKey;
    uint8_t* m_publicKey;
    uint16_t m_publicKeyLength;
    uint16_t m_encryptionBytesLength;
    uint8_t* m_encryptionBytes;


    /**
     * Generates the server id which is sent to the client
     * for minecraft.net session validation.
     */
    void generateId();
    void generateEncryptionBytes(short length);

  public:
    typedef boost::shared_ptr<Mineserver::Network_Authenticator> pointer_t;

    Network_Authenticator();
    virtual ~Network_Authenticator();

    uint8_t* getPublicKey();
    int16_t getPublicKeyLength();
    uint8_t* getEncryptionBytes();
    uint16_t getEncryptionBytesLength();

    int decryptMessage(std::string* message);
    int encryptMessage(std::string* message);
    bool verifyEncryptionBytes(short length, const uint8_t*);
    uint8_t* decryptSymmetricKey(short length, uint8_t* encryptedBytes);

  };
}
#endif	/* AUTHENTICATOR_H */

