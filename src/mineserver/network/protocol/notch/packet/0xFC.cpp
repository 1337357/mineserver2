/*
  Copyright (c) 2013, The Mineserver Project
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
#include <mineserver/byteorder.h>
#include <mineserver/network/message/encryptionresponse.h>
#include <mineserver/network/protocol/notch/packet.h>
#include <mineserver/network/protocol/notch/packet/0xFC.h>

int Mineserver::Network_Protocol_Notch_Packet_0xFC::_read(Mineserver::Network_Protocol_Notch_PacketStream& ps, Mineserver::Network_Message** message)
{
  //Mineserver::Network_Message_Kick* msg = new Mineserver::Network_Message_Kick;
  Mineserver::Network_Message_EncryptionResponse* msg = new Mineserver::Network_Message_EncryptionResponse;
  *message = msg;

  ps >> msg->mid >> msg->sharedSecretLength;
  uint8_t shared_secret[msg->sharedSecretLength];
  for(unsigned short i = 0; i < msg->sharedSecretLength; i++){
    ps >> shared_secret[i];
  }
  msg->sharedSecret = shared_secret;
  ps >> msg->verifyTokenLength;
  uint8_t verify_token[msg->verifyTokenLength];
  for(unsigned short i = 0; i < msg->verifyTokenLength; i++){
    ps >> verify_token[i];
  }
  msg->verifyToken = verify_token;

  //display the data for testing purposes.
  std::cout << "Encryption Response data: \n" <<
      "sharedSecretLength: " << (int)msg->sharedSecretLength <<
      "\nsharedSecret:" << std::endl;
  for(int i = 0; i < msg->sharedSecretLength; i++){
    printf("%02x:", (int)msg->sharedSecret[i]);
  }

  std::cout << "\nverifyTokenLength: " <<
      msg->verifyTokenLength <<
      "\nverifyToken: " << std::endl;
  for(int i = 0; i < (int)msg->verifyTokenLength; i++){
    printf("%02x:", (int)msg->verifyToken[i]);
  }
  printf("\n");

  return STATE_GOOD;
}

int Mineserver::Network_Protocol_Notch_Packet_0xFC::_write(Mineserver::Network_Protocol_Notch_PacketStream& ps, const Mineserver::Network_Message& message)
{
  //const Mineserver::Network_Message_Kick* msg = static_cast<const Mineserver::Network_Message_Kick*>(&message);
  const Mineserver::Network_Message_EncryptionResponse* msg = static_cast<const Mineserver::Network_Message_EncryptionResponse*>(&message);

  ps << msg->mid << msg->sharedSecretLength;
  for(unsigned int i = 0; i < msg->sharedSecretLength; i++){
    ps << msg->sharedSecret[i];
  }
  ps << msg->verifyTokenLength;
  for(unsigned int i = 0; i < msg->verifyTokenLength; i++){
    ps << msg->verifyToken[i];
  }

  return STATE_GOOD;
}
