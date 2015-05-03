// websocket.h -- WebSocket protocol related functions
// Copyright (C) 2008-2015 Markus Gutschke <markus@shellinabox.com>
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// In addition to these license terms, the author grants the following
// additional rights:
//
// If you modify this program, or any covered work, by linking or
// combining it with the OpenSSL project's OpenSSL library (or a
// modified version of that library), containing parts covered by the
// terms of the OpenSSL or SSLeay licenses, the author
// grants you additional permission to convey the resulting work.
// Corresponding Source for a non-source form of such a combination
// shall include the source code for the parts of OpenSSL used as well
// as that of the covered work.
//
// You may at your option choose to remove this additional permission from
// the work, or from any part of it.
//
// It is possible to build this program in a way that it loads OpenSSL
// libraries at run-time. If doing so, the following notices are required
// by the OpenSSL and SSLeay licenses:
//
// This product includes software developed by the OpenSSL Project
// for use in the OpenSSL Toolkit. (http://www.openssl.org/)
//
// This product includes cryptographic software written by Eric Young
// (eay@cryptsoft.com)
//
// The most up-to-date version of this program is always available from
// http://shellinabox.com

#ifndef WEBSOCKET_H__
#define WEBSOCKET_H__

struct WebSocketHeader {
  unsigned char      fin;
  unsigned char      rsv1;
  unsigned char      rsv2;
  unsigned char      rsv3;
  unsigned char      opcode;
  unsigned char      masked;
  unsigned char *    payload;
  unsigned char      payloadMask[4];
  unsigned long long payloadLen;
  int                payloadOffset;
};

#define WS_HEAD_B0_FIN    0x80
#define WS_HEAD_B0_RSV1   0x40
#define WS_HEAD_B0_RSV2   0x20
#define WS_HEAD_B0_RSV3   0x10
#define WS_HEAD_B0_OPCODE 0x0F
#define WS_HEAD_B1_MASK   0x80
#define WS_HEAD_B1_LENGTH 0x7F

#define WS_OPCODE_FRAME_CONTINUE 0x00
#define WS_OPCODE_FRAME_TEXT     0x01
#define WS_OPCODE_FRAME_BINARY   0x02
#define WS_OPCODE_CTL_CLOSE      0x08
#define WS_OPCODE_CTL_PING       0x09
#define WS_OPCODE_CTL_PONG       0x0A

struct WebSocketHeader *webSocketHeaderRead(const char *msg, int len);

char *webSocketResponseClose(const char *msg, int len);
char *webSocketResponsePingPong(const char *msg, int len, int opcode);

char *webSocketPayloadDecode(const char *payload, int payloadLen,
                             const unsigned char *payloadMask);
char *webSocketPayloadEncode(const char *payload, int payloadLen,
                             const unsigned char *payloadMask);

int webSocketHandshakeValidate(struct HttpConnection *http,
                               const char **key, const char **protocol);
char *webSocketHandshakeResponse(const char *key, const char *protocol);

#endif
