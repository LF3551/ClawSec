#ifndef CLAWSEC_MUX_H
#define CLAWSEC_MUX_H

#include <stddef.h>
#include <stdint.h>

/*
 * Stream multiplexer carried inside the encrypted channel.
 *
 * Frame: [stream_id(1)][type(1)][length(2 BE)][payload]
 *
 * Version 1 (ClawSec 3.x / 4.0): OPEN (empty), DATA, CLOSE; ids 1..63.
 * Version 2 (ClawSec 4.1+), enabled per session once the peer's HELLO has
 * been received (a v1 peer ignores unknown frame types, so v1 and v2
 * endpoints interoperate with v1 semantics):
 *   HELLO   stream 0, payload [version]
 *   OPEN    payload [flags] [host_len host port_be]  (target: SOCKS only)
 *           flags & MUX_OPEN_FC: the stream uses flow control and FIN
 *   REPLY   payload [status]: result of the server's connect (v2 streams)
 *   FIN     the sender will send no more DATA (half-close)
 *   WINDOW  payload [u32 BE]: the receiver consumed this many bytes
 *   ids 1..255
 */

#define MUX_DATA    0x01
#define MUX_OPEN    0x02
#define MUX_CLOSE   0x03
#define MUX_HELLO   0x04
#define MUX_REPLY   0x05
#define MUX_FIN     0x06
#define MUX_WINDOW  0x07

#define MUX_VERSION        2
#define MUX_OPEN_FC        0x01

#define MUX_REPLY_OK       0
#define MUX_REPLY_FAIL     1
#define MUX_REPLY_DENIED   2

/* Stream ids: 1..MUX_V1_STREAMS-1 with a v1 peer, 1..MUX_MAX_STREAMS-1 with v2 */
#define MUX_V1_STREAMS  64
#define MUX_MAX_STREAMS 256

/* Per-stream receive window (v2 flow control) */
#define MUX_WINDOW_SIZE (256 * 1024)

/* Frame header: stream_id(1) + type(1) + len(2) = 4 bytes */
#define MUX_HDR_SIZE 4

/* Max payload per frame: a whole frame (header + payload) must fit into one
 * encrypted message of at most FARM9_MAX_MSG (8192) bytes. */
#define MUX_MAX_PAYLOAD (8192 - MUX_HDR_SIZE)

typedef struct {
    unsigned char stream_id;
    unsigned char type;
    unsigned short length;
} mux_header_t;

/* Encode frame header into 4-byte buffer. Returns MUX_HDR_SIZE. */
int mux_encode_header(unsigned char *buf, unsigned char stream_id,
                      unsigned char type, unsigned short length);

/* Decode frame header from 4-byte buffer. Returns 0 or -1. */
int mux_decode_header(const unsigned char *buf, mux_header_t *hdr);

/* Write a mux frame through encrypted channel. Returns payload len or -1. */
int mux_write_frame(int sockfd, unsigned char stream_id,
                    unsigned char type, const void *data, size_t len);

/*
 * Read a mux frame from encrypted channel.
 * Returns: >0 payload len, 0 with hdr.type>0 = valid empty frame,
 *          0 with hdr.type==0 = EOF, <0 = error.
 */
int mux_read_frame(int sockfd, mux_header_t *hdr, void *buf, size_t buflen);

/* -L --mux, server: every stream is connected to fwd_host:fwd_port */
int mux_relay_server(int enc_fd, const char *fwd_host, const char *fwd_port);

/* -L --mux, client: accept local connections on listen_host:local_port
 * (listen_host NULL = all interfaces) */
int mux_relay_client(int enc_fd, const char *listen_host, const char *local_port);

/* SOCKS5 over mux v2. Server: each OPEN names its destination, checked with
 * the SOCKS destination policy. Client: serves SOCKS5 on listen_fd (already
 * listening) and opens one stream per CONNECT, all concurrently. */
int mux_socks_server(int enc_fd);
int mux_socks_client(int enc_fd, int listen_fd);

/* Encode an OPEN payload for a v2 stream. Returns its length or -1. */
int mux_encode_open(unsigned char *buf, size_t buflen, unsigned char flags,
                    const char *host, uint16_t port);
/* Decode an OPEN payload. host may be NULL if no target is expected.
 * Returns 0 (has_target set), or -1 if malformed. */
int mux_decode_open(const unsigned char *buf, size_t len, unsigned char *flags,
                    char *host, size_t hostlen, uint16_t *port, int *has_target);

/* SOCKS5 parsing on bytes accumulated from a local client.
 * Greeting: 0 = need more, >0 = bytes consumed (answer 05 00), -1 = invalid.
 * Request:  0 = need more, >0 = bytes consumed with host/port filled,
 *           -1 = invalid or unsupported; *reply_code is the SOCKS5 reply
 *           to send before closing. */
int mux_socks_parse_greeting(const unsigned char *buf, size_t len);
int mux_socks_parse_request(const unsigned char *buf, size_t len, char *host,
                            size_t hostlen, uint16_t *port, unsigned char *reply_code);

extern int g_mux;

#endif
