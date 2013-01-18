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
}

void Mineserver::Network_Client::start()
{
  std::cout << "Client connection starting" << std::endl;
  m_encryptionPending = false; //this will be set to true when about to send 0xFC response.
  m_encrypted = false;
  this->generateVerificationToken(4);
  read();
}

void Mineserver::Network_Client::stop()
{
  m_socket.close();
  m_alive = false;
}

/**
 * Reads incoming bytes which get stored to m_tmp.
 *
 * calls handleRead() callback function which will
 * decrypt bytes if needed before parsing them into
 * network messages.
 */
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
/**
 * Transmit the messages to the client.
 *
 * the m_outgoing message objects are composed into the bytes in the correct
 * format for the client and are subsequently added to the m_outgoingBuffer.
 *
 * If encryption is enabled, EVP_EncryptUpdate will replace the bytes in the
 * m_outgoingBuffer with the AES256 ones.
 *
 * The m_outgoingBuffer will then be sent asynchronously, calling the handleWrite()
 * function with the bytes transfered once complete, or any errors that occured.
 */
void Mineserver::Network_Client::write()
{
  for (std::vector<Mineserver::Network_Message::pointer_t>::iterator it=m_outgoing.begin();it!=m_outgoing.end();++it) {
    printf("Trying to send message ID: %02x\n", (*it)->mid);
    m_protocol->compose(m_outgoingBuffer, **it);
    //if its the acknowledging 0xFC, set the encryption in the write callback (handleWrite)
    if( (*it)->mid == 0xFC ){
      m_encryptionPending = true;
    }
  }

  //clear the 'messages' objects list now that they have been composed into bytes the client understands.
  m_outgoing.clear();

  //overwrite the values in the buffer with the AES encrypted equalivant.
  if(m_encrypted)
  {
    int encyptedLength;

    if(!EVP_EncryptUpdate(&m_encryptionContext, &m_outgoingBuffer[0], &encyptedLength, &m_outgoingBuffer[0], m_outgoingBuffer.size())){
      std::cout << "There was an ERROR encrypting the bytes" << std::endl;
      ERR_print_errors_fp(stdout);
    }

  }//end if IF m_encrypted

  std::cout << "We want to send " << m_outgoingBuffer.size() << " bytes. They are: " << std::endl;
  for(unsigned int i = 0; i < m_outgoingBuffer.size(); i++){
	  printf("%02x:", m_outgoingBuffer[i]);
  }
  std::cout << std::endl;

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
      uint8_t* encrypted = (uint8_t*)m_tmp.c_array();
      uint8_t* decrypted;
      int decryptedLength;
      decrypted = new uint8_t[n];

      if(!EVP_DecryptUpdate(&m_decryptionContext, decrypted, &decryptedLength, (const uint8_t*)encrypted, n)){
        std::cout << "There was an error decrypting the bytes" << std::endl;
        ERR_print_errors_fp(stdout);
      }

      m_incomingBuffer.insert(m_incomingBuffer.end(), decrypted, decrypted + n);

      std::cout << "Got bytes (been decrypted): ";

      for(unsigned int i = 0; i < n; i++){
        printf("%02x:", decrypted[i]);
      }
      std::cout << std::endl;

      delete[] decrypted;
    }

    else
    {
      //we're not encrypted yet, just read the message as usual
      m_incomingBuffer.insert(m_incomingBuffer.end(), m_tmp.begin(), m_tmp.begin() + n);
      printf("Got bytes (not encrypted): ");
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

/**
 * The boost write() call-back. Called once the outgoing bytes have been sent sent.
 * n is the amount of bytes that were actually sent down the tubes. It calls
 * write() again if there are still bytes remaining in the buffer.
 */
void Mineserver::Network_Client::handleWrite(const boost::system::error_code& e, size_t n)
{
	m_outgoingBuffer.erase(m_outgoingBuffer.begin(), m_outgoingBuffer.begin() + n);
	std::cout << "Wrote " << n << " bytes, " << m_outgoingBuffer.size() << " left." << std::endl;
  m_writing = false;

  //did we just send the 0xFC packet? (last plaintext one). Then start encryption.
  if(m_encryptionPending){
    m_encrypted = true; //bytes will be en/decrypted in write() and handleRead()
    m_encryptionPending = false; // to stop run this condition running again and again.
    std::cout << "Encryption has started" << std::endl;
  }

  if (m_outgoingBuffer.size() > 0) {
    write();
  }
}

/**
 * Takes the RSA decrypted symmetric key, stores it and initializes
 * the encryption and decryption contexts.
 *
 */
void Mineserver::Network_Client::startEncryption(uint8_t* symmetricKey)
{
  m_symmetricKey = symmetricKey;
  EVP_CIPHER_CTX_init(&m_encryptionContext);
  EVP_EncryptInit_ex(&m_encryptionContext, EVP_aes_128_cfb8(), NULL, m_symmetricKey, m_symmetricKey);
  EVP_CIPHER_CTX_init(&m_decryptionContext);
  EVP_DecryptInit_ex(&m_decryptionContext, EVP_aes_128_cfb8(), NULL, m_symmetricKey, m_symmetricKey);
}

/**
 * Sets the state of the clients network tx/rx to be AES encrypted or not.
 * @deprectated - not being used.
 */
void Mineserver::Network_Client::setEncrypted(bool state){
  m_encrypted = state;
}

/**
 * Generate the verification token for the 0xFD packet,
 * client should return these bytes encrypted with the public key.
 */
void Mineserver::Network_Client::generateVerificationToken(short length)
{
  std::cout << "Generating verification token for new client." << std::endl;
  this->m_verificationToken.reserve(length);
  for(int i=0; i<length;i++)
  {
    m_verificationToken.push_back((uint8_t) rand() % 256);
    printf("%02x:", m_verificationToken[i]);
  }
  std::cout << std::endl;
}

/**
 * Gets the encryption verification token for checking public key is working OK.
 */
std::vector<uint8_t> Mineserver::Network_Client::getVerificationToken(){
  return m_verificationToken;
}
