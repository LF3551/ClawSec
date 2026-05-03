#ifndef CLAWSEC_MUX_H
#define CLAWSEC_MUX_H

#include <stddef.h>

/* Mux frame types */
#define MUX_DATA   0x01
#define MUX_OPEN   0x02
#define MUX_CLOSE  0x03

/* Max concurrent streams */
#define MUX_MAX_STREAMS 64

/* Frame header: stream_id(1) + type(1) + len(2) = 4 bytes */
#define MUX_HDR_SIZE 4

/* Max payload per frame */
#define MUX_MAX_PAYLOAD 8192

/* Frame header structure */
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

/* Server-side mux: demux encrypted frames to target connections */
int mux_relay_server(int enc_fd, const char *fwd_host, const char *fwd_port);

/* Client-side mux: accept local connections, mux through encrypted tunnel */
int mux_relay_client(int enc_fd, const char *local_port);

extern int g_mux;

#endif
