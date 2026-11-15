#ifndef CLAWSEC_FILETX_H
#define CLAWSEC_FILETX_H

#include <stdint.h>

/*
 * File Transfer Protocol over encrypted ClawSec tunnel.
 *
 * Wire protocol (after ECDHE):
 *   Sender → Receiver:  HEADER
 *     [8: file_size_be][32: sha256_hash][2: name_len_be][N: filename]
 *
 *   Receiver → Sender:  RESUME OFFSET
 *     [8: offset_be]  (0 = fresh transfer, >0 = resume from this byte)
 *
 *   Sender → Receiver:  DATA CHUNKS (streaming, each up to 8000 bytes)
 *     (raw encrypted writes until file_size - offset bytes sent)
 *
 *   Receiver → Sender:  VERIFY
 *     [1: status]  (0 = SHA-256 matched, 1 = mismatch)
 *
 * Features:
 *   - Progress bar with % and speed
 *   - Resume on reconnect (receiver keeps <name>.clawsec-part)
 *   - SHA-256 end-to-end verification
 *   - No file size limit (streams in chunks)
 */

#define FILETX_CHUNK_SIZE  8000  /* < FARM9_MAX_MSG to avoid fragmentation */
#define FILETX_HDR_SIZE    42    /* 8 + 32 + 2 */

/* Send a file over encrypted tunnel. Returns 0 on success, -1 on error. */
int filetx_send(int tunnel_fd, const char *filepath);

/* Receive a file from encrypted tunnel. dir = output directory (NULL = cwd).
 * Data is written to "<name>.clawsec-part" (our own regular file, opened
 * with O_NOFOLLOW, single link) and renamed to <name> only after the
 * SHA-256 matches, so symlinks/hardlinks in the directory are never written
 * through and a failed transfer never touches an existing file.
 * Returns 0 on success, -1 on error. */
int filetx_recv(int tunnel_fd, const char *output_dir);

/* Make a peer-supplied file name safe to create in a directory: path
 * separators and control characters become '_', a leading '.' becomes '_'
 * (no hidden files, no "." / ".."), and an empty name becomes
 * "received.bin". name must be NUL-terminated; it is modified in place. */
void filetx_sanitize_name(char *name);

#define FILETX_PART_SUFFIX ".clawsec-part"

#endif
