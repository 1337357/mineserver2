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

#include <mineserver/byteorder.h>
#include <mineserver/network/message/encryptionrequest.h>
#include <mineserver/network/protocol/notch/packet.h>
#include <mineserver/network/protocol/notch/packet/0xFD.h>

int Mineserver::Network_Protocol_Notch_Packet_0xFD::_read(Mineserver::Network_Protocol_Notch_PacketStream& ps, Mineserver::Network_Message** message)
{
  //do nothing. we don't read this packet.
  return STATE_GOOD;
}

int Mineserver::Network_Protocol_Notch_Packet_0xFD::_write(Mineserver::Network_Protocol_Notch_PacketStream& ps, const Mineserver::Network_Message& message)
{

  const Mineserver::Network_Message_EncryptionRequest* msg = static_cast<const Mineserver::Network_Message_EncryptionRequest*>(&message);
  ps << msg->mid << msg->serverId << msg->publicKeyLength;

  //send each byte of the public key array to the stream.
  for(int i = 0; i < msg->publicKeyLength; i++){
    ps << msg->publicKey[i];
  }
  //send the length of the 'encryption bytes'
  ps << msg->verifyTokenLength;

  //now send each byte of the encryption bytes array one at a time
  for(int i = 0; i < msg->verifyTokenLength; i++){
    ps << msg->verifyToken[i];
  }
  return STATE_GOOD;
}
