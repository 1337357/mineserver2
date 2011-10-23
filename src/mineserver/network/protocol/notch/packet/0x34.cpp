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

#include <mineserver/byteorder.h>
#include <mineserver/network/message.h>
#include <mineserver/network/protocol/notch/packetstream.h>
#include <mineserver/network/protocol/notch/packet.h>
#include <mineserver/network/protocol/notch/packet/0x34.h>

int Mineserver::Network_Protocol_Notch_Packet_0x34::read(packet_stream_t& ps)
{
  ps >> m->mid >> m->x >> m->z >> m->num;
  m->coordinate.reserve(m->num*2);
  ps.bytesTo(reinterpret_cast<uint8_t*>(&(m->coordinate[0])), m->num*2);
  m->type.reserve(m->num);
  ps.bytesTo(reinterpret_cast<uint8_t*>(&(m->type[0])), m->num);
  m->meta.reserve(m->num);
  ps.bytesTo(reinterpret_cast<uint8_t*>(&(m->meta[0])), m->num);

  if (ps.isValid()) {
    ps.remove();
    return STATE_MORE;
  } else {
    return STATE_NEEDMOREDATA;
  }
}

void Mineserver::Network_Protocol_Notch_Packet_0x34::write(packet_stream_t& ps)
{
  ps << m->mid << m->x << m->z << m->num;
  ps.bytesFrom(reinterpret_cast<uint8_t*>(&(m->coordinate[0])), m->num*2);
  ps.bytesFrom(reinterpret_cast<uint8_t*>(&(m->type[0])), m->num);
  ps.bytesFrom(reinterpret_cast<uint8_t*>(&(m->meta[0])), m->num);
}
