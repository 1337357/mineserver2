/*
  Copyright (c) 2011, The Mineserver Project
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
#include <vector>
#include <iostream>
#include <cstdio>
#include <stdint.h>

#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>
#include <boost/asio.hpp>

#include <mineserver/byteorder.h>
#include <mineserver/localization.h>
#include <mineserver/network/client.h>
#include <mineserver/network/message/keepalive.h>
#include <mineserver/network/message/kick.h>

void Mineserver::Network_Client::run()
{
  m_inactiveTicks++;
  m_inactiveTicksReply++;

  // client disconnects after one minute of us not responding.
  // we do not have to reply with the same keepalive id that they sent us.
  // --
  // we shall send this 3 times per minute, if we need more, increase this.
  // 1200 ticks = 1 minute, 400 ticks = 20 seconds, 20 * 3 = 1 minute
  // client has 3 times to see if we are responding or not.
  if (m_inactiveTicksReply >= 400)
  {
    boost::shared_ptr<Mineserver::Network_Message_KeepAlive> response = boost::make_shared<Mineserver::Network_Message_KeepAlive>();
    response->mid = 0x00;
    response->keepalive_id = 0;
    outgoing().push_back(response);
    resetInactiveTicksReply();
  }
}

void Mineserver::Network_Client::resetInactiveTicks()
{
  m_inactiveTicks = 0;
}

void Mineserver::Network_Client::resetInactiveTicksReply()
{
  m_inactiveTicksReply = 0;
}

void Mineserver::Network_Client::timedOut()
{
  boost::shared_ptr<Mineserver::Network_Message_Kick> responseMessage(new Mineserver::Network_Message_Kick);
  responseMessage->mid = 0xFF;
  responseMessage->reason = "Timed-out";
  outgoing().push_back(responseMessage);
  stop();
  // Jailout2000: Does the kick message get sent before closing the socket? I guess it doesn't *really* matter...
}

void Mineserver::Network_Client::start()
{
  read();
}

void Mineserver::Network_Client::stop()
{
  m_socket.close();
  m_alive = false;
}

void Mineserver::Network_Client::read()
{
  m_socket.async_read_some(
    boost::asio::buffer(m_tmp),
    boost::bind(
      &Mineserver::Network_Client::handleRead,
      shared_from_this(),
      boost::asio::placeholders::error,
      boost::asio::placeholders::bytes_transferred
    )
  );
}

void Mineserver::Network_Client::write()
{
  for (std::vector<Mineserver::Network_Message::pointer_t>::iterator it=m_outgoing.begin();it!=m_outgoing.end();++it) {
    printf("Trying to send message ID: %02x\n", (*it)->mid);
    m_protocol->compose(m_outgoingBuffer, **it);
  }

  m_outgoing.clear();

  if(false)
  {
    std::cout << "crypted write() called" << std::endl;
    std::cout << "Attempting to decrypt incoming data" << std::endl;
    uint8_t decrypted[m_outgoingBuffer.size()];
    for(unsigned int i = 0; i < m_outgoingBuffer.size(); i++){
      decrypted[i] = m_outgoingBuffer[i];
    }
    uint8_t* encrypted;
    int encryptedLength;
    encrypted = new uint8_t[m_outgoingBuffer.size()];

    EVP_EncryptUpdate(&m_encryptionContext, decrypted, &encryptedLength, (const uint8_t*)encrypted, m_outgoingBuffer.size());

    m_outgoingBuffer.clear();
    for(int i = 0; i < encryptedLength; i++){
      m_outgoingBuffer.push_back(encrypted[i]);
    }

    delete[] encrypted;
  }

  if(m_outgoingBuffer.size() > 0){
    printf("We want to send %i bytes\n", m_outgoingBuffer.size());
  }

  if (!m_writing)
  {
    m_writing = true;

    m_socket.async_write_some(
      boost::asio::buffer(m_outgoingBuffer),
      boost::bind(
        &Mineserver::Network_Client::handleWrite,
        shared_from_this(),
        boost::asio::placeholders::error,
        boost::asio::placeholders::bytes_transferred
      )
    );
  }
}

void Mineserver::Network_Client::handleRead(const boost::system::error_code& e, size_t n)
{
  if (!e) {
    if(this->m_encrypted){
      std::cout << "Attempting to decrypt incoming data" << std::endl;
      uint8_t* encrypted = (uint8_t*)m_tmp.c_array();
      uint8_t* decrypted;
      int decryptedLength;
      decrypted = new uint8_t[n];

      EVP_DecryptUpdate(&m_decryptionContext, decrypted, &decryptedLength, (const uint8_t*)encrypted, n);

      m_incomingBuffer.insert(m_incomingBuffer.end(), decrypted, decrypted + n);

      std::cout << "Got bytes: ";

      for(unsigned int i = 0; i < n; i++){
        std::cout << std::hex << (int)decrypted[i];
      }
      std::cout << std::endl;

      delete[] decrypted;
    }

    else {
      //not encrypted yet, just read the message as usual
      m_incomingBuffer.insert(m_incomingBuffer.end(), m_tmp.begin(), m_tmp.begin() + n);
      printf("Got bytes: ");
      for (boost::array<uint8_t, 8192>::iterator it=m_tmp.begin();it!=m_tmp.begin()+n;++it) {
        printf("%02x:", *it);
      }
      printf("\n");
    }

    //now try make sense of the bytes and convert them into message objects
    int state;
    do {
      Mineserver::Network_Message* message = NULL;

      state = m_protocol->parse(m_incomingBuffer, &message);

      if (state == Mineserver::Network_Protocol::STATE_GOOD) {
        m_incoming.push_back(Mineserver::Network_Message::pointer_t(message));
      }

      printf("State is: %d\n", state);
    } while (state == Mineserver::Network_Protocol::STATE_GOOD);

    read();
  } else if (e != boost::asio::error::operation_aborted) {
    stop();
  }
}

void Mineserver::Network_Client::handleWrite(const boost::system::error_code& e, size_t n)
{
	m_outgoingBuffer.erase(m_outgoingBuffer.begin(), m_outgoingBuffer.begin() + n);
	if(n > 0 && m_outgoingBuffer.size() > 0){
    printf("Wrote %u bytes, %u left\n", n, m_outgoingBuffer.size());
	}
  m_writing = false;

  if (m_outgoingBuffer.size() > 0) {
    write();
  }
}
/**
 * Takes the RSA decrypted symmetric key, stores it and starts encrypted
 * stream traffic.
 */
void Mineserver::Network_Client::startEncryption(uint8_t* symmetricKey)
{
  m_symmetricKey = symmetricKey;
  EVP_CIPHER_CTX_init(&m_encryptionContext);
  EVP_EncryptInit_ex(&m_encryptionContext, EVP_aes_128_cfb8(), NULL, m_symmetricKey, m_symmetricKey);
  EVP_CIPHER_CTX_init(&m_decryptionContext);
  EVP_DecryptInit_ex(&m_decryptionContext, EVP_aes_128_cfb8(), NULL, m_symmetricKey, m_symmetricKey);

  m_encrypted = true;
}
