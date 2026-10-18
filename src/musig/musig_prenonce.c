#include "musig_prenonce.h"

/* Local headers */
#include "crypto.h"

static const uint8_t prenonce_tag[] =
    {'M', 'u', 'S', 'i', 'g', '2', 'P', 'r', 'e', 'n', 'o', 'n', 'c', 'e'};

bool musig_prenonce_derive(const uint8_t nonce_init[static 32],
                           uint32_t j,
                           uint32_t i,
                           uint32_t k,
                           const uint8_t wallet_id[static 32],
                           const uint8_t sk[static 32],
                           const plain_pk_t pk,
                           const plain_pk_t agg_pk,
                           musig_secnonce_t *secnonce,
                           musig_pubnonce_t *pubnonce) {
    cx_sha256_t hash_context;
    crypto_tr_tagged_hash_init(&hash_context, prenonce_tag, sizeof(prenonce_tag));
    crypto_hash_update(&hash_context.header, nonce_init, 32);
    crypto_hash_update_u32(&hash_context.header, j);
    crypto_hash_update_u32(&hash_context.header, i);
    crypto_hash_update_u32(&hash_context.header, k);
    crypto_hash_update(&hash_context.header, wallet_id, 32);
    crypto_hash_update(&hash_context.header, pk, sizeof(plain_pk_t));
    crypto_hash_update(&hash_context.header, agg_pk, sizeof(plain_pk_t));

    uint8_t rand[CX_SHA256_SIZE];
    crypto_hash_digest(&hash_context.header, rand, sizeof(rand));
    explicit_bzero(&hash_context, sizeof(hash_context));

    uint8_t extra_in[4];
    write_u32_be(extra_in, 0, j);

    int res = musig_nonce_gen_ext(rand,
                                  sizeof(rand),
                                  sk,
                                  pk,
                                  agg_pk + 1,  // x-only
                                  NULL,
                                  0,
                                  extra_in,
                                  sizeof(extra_in),
                                  secnonce,
                                  pubnonce);
    explicit_bzero(rand, sizeof(rand));

    if (res < 0) {
        explicit_bzero(secnonce, sizeof(*secnonce));
        return false;
    }
    return true;
}
