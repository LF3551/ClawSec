/*
 * fuzz_spake2.c — the SPAKE2 peer message and AAD come from the network.
 * Input: [peer point (65)] [AAD (rest)]. Both roles are exercised; invalid
 * points must be rejected without crashes, leaks or UB.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "fuzz_common.h"
#include "spake2.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const unsigned char w[SPAKE2_SCALAR_LEN] = { 0x2e, 0xe5, 0x79, 0x12, 0x09, 0x9d };
    unsigned char my[SPAKE2_POINT_LEN], ke[SPAKE2_KEY_LEN], c1[SPAKE2_CONF_LEN],
                  c2[SPAKE2_CONF_LEN], h[32], peer[SPAKE2_POINT_LEN] = { 0 };
    if (size > 4096) return 0;
    memcpy(peer, data, size < sizeof(peer) ? size : sizeof(peer));
    const uint8_t *aad = size > sizeof(peer) ? data + sizeof(peer) : NULL;
    size_t aad_len = size > sizeof(peer) ? size - sizeof(peer) : 0;

    for (int role = SPAKE2_ROLE_A; role <= SPAKE2_ROLE_B; role++) {
        spake2_ctx *c = spake2_new(role, w, (const unsigned char *)"a", 1,
                                   (const unsigned char *)"b", 1);
        if (c && spake2_message(c, my) == 0)
            (void)spake2_finish(c, peer, aad, aad_len, ke, c1, c2, h);
        spake2_free(c);
    }
    return 0;
}
