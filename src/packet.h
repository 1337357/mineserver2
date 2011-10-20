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

#ifndef _PACKET_H
#define _PACKET_H

#include "byteorder.h"
#include "packetstream.h"

namespace Mineserver
{
  // Packet IDs
  // See: http://www.wiki.vg/Protocol
  enum
  {
    PACKET_KEEP_ALIVE = 0x00,
    PACKET_LOGIN = 0x01,
    PACKET_HANDSHAKE = 0x02,
    PACKET_CHAT_MESSAGE = 0x03,
    PACKET_TIME_UPDATE = 0x04,
    PACKET_ENTITY_EQUIPMENT = 0x05,
    PACKET_SPAWN_POSITION = 0x06,
    PACKET_USE_ENTITY = 0x07,
    PACKET_UPDATE_HEALTH = 0x08,
    PACKET_RESPAWN = 0x09,
    PACKET_PLAYER = 0x0A,
    PACKET_PLAYER_POSITION = 0x0B,
    PACKET_PLAYER_LOOK = 0x0C,
    PACKET_PLAYER_POSITION_AND_LOOK = 0x0D,
    PACKET_PLAYER_DIGGING = 0x0E,
    PACKET_PLAYER_BLOCK_PLACEMENT = 0x0F,
    PACKET_HOLDING_CHANGE = 0x10,
    PACKET_USE_BED = 0x11,
    PACKET_ANIMATION = 0x12,
    PACKET_ENTITY_ACTION = 0x13,
    PACKET_NAMED_ENTITY_SPAWN = 0x14,
    PACKET_PICKUP_SPAWN = 0x15,
    PACKET_COLLECT_ITEM = 0x16,
    PACKET_ADD_OBJECT_OR_VEHICLE = 0x17,
    PACKET_MOB_SPAWN = 0x18,
    PACKET_PAINTING = 0x19,
    PACKET_EXPERIENCE_ORB = 0x1A,
    PACKET_STANCE_UPDATE = 0x1B,
    PACKET_ENTITY_VELOCITY = 0x1C,
    PACKET_DESTROY_ENTITY = 0x1D,
    PACKET_ENTITY = 0x1E,
    PACKET_ENTITY_RELATIVE_MOVE = 0x1F,
    PACKET_ENTITY_LOOK = 0x20,
    PACKET_ENTITY_LOOK_AND_RELATIVE_MOVE = 0x21,
    PACKET_ENTITY_TELEPORT = 0x22,
    PACKET_ENTITY_STATUS = 0x26,
    PACKET_ATTACH_ENTITY = 0x27,
    PACKET_ENTITY_METADATA = 0x28,
    PACKET_ENTITY_EFFECT = 0x29,
    PACKET_ENTITY_EFFECT_REMOVE = 0x2A,
    PACKET_EXPERIENCE = 0x2B,
    PACKET_PRE_CHUNK = 0x32,
    PACKET_MAP_CHUNK = 0x33,
    PACKET_MULTI_BLOCK_CHANGE = 0x34,
    PACKET_BLOCK_CHANGE = 0x35,
    PACKET_BLOCK_ACTION = 0x36,
    PACKET_EXPLOSION = 0x3C,
    PACKET_SOUND_EFFECT = 0x3D,
    PACKET_NEW_OR_INVALID_STATE = 0x46,
    PACKET_THUNDERBOLT = 0x47,
    PACKET_OPEN_WINDOW = 0x64,
    PACKET_CLOSE_WINDOW = 0x65,
    PACKET_WINDOW_CLICK = 0x66,
    PACKET_SET_SLOT = 0x67,
    PACKET_WINDOW_ITEMS = 0x68,
    PACKET_UPDATE_PROGRESS_BAR = 0x69,
    PACKET_TRANSACTION = 0x6A,
    PACKET_CREATIVE_INVENTORY_ACTION = 0x6B,
    PACKET_ENCHANT_ITEM = 0x6C,
    PACKET_UPDATE_SIGN = 0x82,
    PACKET_ITEM_DATA = 0x83,
    PACKET_INCREMENT_STATISTIC = 0xC8,
    PACKET_PLAYER_LIST_ITEM = 0xC9,
    PACKET_LIST_PING = 0xFE,
    PACKET_KICK = 0xFF,
  };

  class Packet
  {
  public:
    uint8_t pid;
  public:
    virtual void read(Mineserver::PacketStream& ps) = 0;
    virtual void write(Mineserver::PacketStream& ps) = 0;
  };
}

#endif
