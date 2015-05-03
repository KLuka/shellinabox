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

#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logging/logging.h"
#include "libhttp/httpconnection.h"
#include "libhttp/websocket.h"

static char *webSocketAcceptToken(const char *key);

struct WebSocketHeader *webSocketHeaderRead(const char *msg, int len) {

  struct WebSocketHeader *header;
  check(header              = malloc(sizeof(struct WebSocketHeader)));
  header->fin               = !!(msg[0] & WS_HEAD_B0_FIN);
  header->rsv1              = !!(msg[0] & WS_HEAD_B0_RSV1);
  header->rsv2              = !!(msg[0] & WS_HEAD_B0_RSV2);
  header->rsv3              = !!(msg[0] & WS_HEAD_B0_RSV3);
  header->opcode            = (((msg[0] & WS_HEAD_B0_OPCODE)));
  header->masked            = !!(msg[1] & WS_HEAD_B1_MASK);
  header->payloadLen        = (((msg[1] & WS_HEAD_B1_LENGTH)));

  int maskLen               = header->masked ? 4 : 0;
  switch (header->payloadLen) {
    case 0x7E:
      // Use 2 bytes for payload length
	  header->payloadLen    = ((unsigned long long)msg[3] & 0xFF);
	  header->payloadLen   |= ((unsigned long long)msg[2] & 0xFF) << 8;
	  header->payloadOffset = maskLen + 2 + 2;
      break;
	case 0x7F:
      // Use 8 bytes for payload length
	  header->payloadLen    = ((unsigned long long)msg[9] & 0xFF);
	  header->payloadLen   |= ((unsigned long long)msg[8] & 0xFF) << 8;
	  header->payloadLen   |= ((unsigned long long)msg[7] & 0xFF) << 16;
	  header->payloadLen   |= ((unsigned long long)msg[6] & 0xFF) << 24;
	  header->payloadLen   |= ((unsigned long long)msg[5] & 0xFF) << 32;
	  header->payloadLen   |= ((unsigned long long)msg[4] & 0xFF) << 40;
	  header->payloadLen   |= ((unsigned long long)msg[3] & 0xFF) << 48;
	  header->payloadLen   |= ((unsigned long long)msg[2] & 0xFF) << 56;
	  header->payloadOffset = maskLen + 2 + 8;
      break;
    default:
	  header->payloadOffset = maskLen + 2;
  }

  if (maskLen) {
    // Mask key is four bytes long and is located before payload
    memcpy(header->payloadMask, &msg[header->payloadOffset - 4], 4);
  }

  return header;
}

char *webSocketResponseClose(const char *msg, int len) {
  char *close;
  check(close = malloc(len));

  // Use same frame for response
  memcpy(close, msg, len);
  return close;
}

char *webSocketResponsePingPong(const char *msg, int len, int opcode) {
  char *pingPong;
  check(pingPong = malloc(len));

  // Use same frame for response, except with changed opcode
  memcpy(pingPong, msg, len);
  if (opcode == WS_OPCODE_CTL_PING) {
    pingPong[0]  = (char) ((msg[0] & 0xF0) | WS_OPCODE_CTL_PONG);
  } else {
    pingPong[0]  = (char) ((msg[0] & 0xF0) | WS_OPCODE_CTL_PING);
  }

  return pingPong;
}

char *webSocketPayloadDecode(const char *payload, int payloadLen,
                             const unsigned char *payloadMask) {
  char *decoded;
  check(decoded = malloc(payloadLen + 1));

  int i;
  for (i = 0; i < payloadLen; i++) {
    decoded[i]  = payload[i] ^ payloadMask[i%4];
  }

  decoded[i]    = '\0';
  return decoded;
}

char *webSocketPayloadEncode(const char *payload, int payloadLen,
                             const unsigned char *payloadMask) {
  char *encoded;
  check(encoded = malloc(payloadLen + 1));

  int i;
  for (i = 0; i < payloadLen; i++) {
    encoded[i]  = payload[i] ^ payloadMask[i%4];
  }

  encoded[i]    = '\0';
  return encoded;
}

#ifndef HAVE_STRCASESTR
static char *strcasestr(const char *haystack, const char *needle) {
  // This algorithm is O(len(haystack)*len(needle)). Much better algorithms
  // are available, but this code is much simpler and performance is not
  // critical for our workloads.
  int len = strlen(needle);
  do {
    if (!strncasecmp(haystack, needle, len)) {
      return haystack;
    }
  } while (*haystack++);
  return NULL;
}
#endif

int webSocketHandshakeValidate(struct HttpConnection *http,
                               const char **key, const char **protocol) {
  // RFC6455 - The handshake from the client looks as follows:
  //
  //    GET /chat HTTP/1.1
  //    Host: server.example.com
  //    Upgrade: websocket
  //    Connection: Upgrade
  //    Origin: http://example.com
  //    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
  //    Sec-WebSocket-Protocol: chat, superchat
  //    Sec-WebSocket-Version: 13
  //
  const char *upgrade     = getFromHashMap(&http->header, "upgrade");
  const char *connection  = getFromHashMap(&http->header, "connection");
  if (!upgrade    || !strcasestr(upgrade, "websocket") ||
      !connection || !strcasestr(connection, "upgrade")) {
    return 0;
  }

  const char *host        = getFromHashMap(&http->header, "host");
  const char *origin      = getFromHashMap(&http->header, "origin");
  if (!host || !origin) {
    return 0;
  }

  for (const char *ptr = host; *ptr; ptr++) {
    if ((unsigned char)*ptr < ' ') {
      return 0;
    }
  }

  for (const char *ptr = origin; *ptr; ptr++) {
    if ((unsigned char)*ptr < ' ') {
      return 0;
    }
  }

  const char *tmpKey      = getFromHashMap(&http->header, "sec-websocket-key");
  const char *version     = getFromHashMap(&http->header, "sec-websocket-version");
  if (!tmpKey || !version) {
    return 0;
  }

  // For now Shellinabox supports only WebSocket version 13
  if (atoi(version) != 13) {
    debug("WS version \"%s\" not supported!", version);
    return 0;
  }

  for (const char *ptr = tmpKey; *ptr; ptr++) {
    if ((unsigned char)*ptr < ' ') {
      return 0;
    }
  }

  *key                    = tmpKey;

  // Optional
  const char *tmpProtocol = getFromHashMap(&http->header, "sec-websocket-protocol");
  if (tmpProtocol) {
    for (const char *ptr = tmpProtocol; *ptr; ptr++) {
      if ((unsigned char)*ptr < ' ') {
        return 0;
      }
    }
    *protocol             = tmpProtocol;
  }

  // Valid WebSocket client handshake
  return 1;
}

char *webSocketHandshakeResponse(const char *key,
                                 const char *protocol) {
  // RFC6455 - The handshake from the server looks as follows:
  //
  //     HTTP/1.1 101 Switching Protocols
  //     Upgrade: websocket
  //     Connection: Upgrade
  //     Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
  //     Sec-WebSocket-Protocol: chat
  //
  char *accept   = webSocketAcceptToken(key);
  char *response = stringPrintf(NULL,
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Accept: %s\r\n"
    "%s%s%s"
    "\r\n",
    accept,
    protocol ? "Sec-WebSocket-Protocol: " : "",
    protocol ? protocol : "",
    protocol ? "\r\n" : "");
  free(accept);
  return response;
}

static char *webSocketAcceptToken(const char *key) {
  char *accept                = NULL;
#if defined(HAVE_OPENSSL)
  // To create "Sec-WebSocket-Accept" token we have to concatenate client key
  // with WebSocket magic number, hash it with SHA1 and then encode it in base64.
  // (See RFC6455)
  char *concatenatedKey       = stringPrintf(NULL,
    "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);

  // Hash concatenated key
  unsigned char hash[20];
  SHA1((unsigned char *) concatenatedKey, strlen(concatenatedKey), hash);
  free(concatenatedKey);

  // Get base64 encoded string
  BIO *b64, *mem;
  check(b64                   = BIO_new(BIO_f_base64()));
  check(mem                   = BIO_new(BIO_s_mem()));
  b64                         = BIO_push(b64, mem);
  BIO_write(b64, hash, 20);
  BIO_flush(b64);
  BUF_MEM *bufferPtr;
  BIO_get_mem_ptr(b64, &bufferPtr);

  check(accept                = malloc(bufferPtr->length));
  memcpy(accept, bufferPtr->data, bufferPtr->length-1);
  accept[bufferPtr->length-1] = 0;

  // Free BIO chain
  BIO_free_all(mem);
#else
  // For now we need OpenSSL headers for SHA1 hashing and base64 encoding.
  // If this is not available we return incorrect token and handle the error
  // on client side.
  debug("OpenSSL is needed for WebSocket support!");
#endif
  return accept ? accept : stringPrintf(NULL, "%s", "invalid");
}
