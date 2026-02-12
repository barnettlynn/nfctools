#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#include <CommonCrypto/CommonCrypto.h>

#if defined(__APPLE__)
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#include <wintypes.h>
#endif

#define MAX_APDU 512
#define SDM_READ_CTR_OFFSET_NONE 0xFFFFFF
#define SDM_UID_LEN_ASCII 14
#define SDM_CTR_LEN_ASCII 6
#define SDM_MAC_LEN_ASCII 16

typedef struct {
    uint8_t kenc[16];
    uint8_t kmac[16];
    uint8_t ti[4];
    uint16_t cmd_ctr;
    uint8_t key_no;
    int authenticated;
} ssm_session_t;

typedef struct {
    int valid;
    int sdm_enabled;
    int sdm_read_ctr_enabled;
    uint8_t file_option;
    uint8_t sdm_options;
    uint8_t sdm_meta_read;
    uint8_t sdm_file_read;
    uint8_t sdm_ctr_ret;
    uint8_t ar1;
    uint8_t ar2;
    uint32_t file_size;
} file_settings_info_t;

typedef struct {
    uint8_t *ndef;
    size_t ndef_len;
    uint32_t uid_offset;
    uint32_t ctr_offset;
    uint32_t mac_input_offset;
    uint32_t mac_offset;
    char url[512];
} sdm_ndef_t;

static int select_ndef_app(SCARDHANDLE card, const SCARD_IO_REQUEST *pio, uint16_t *sw_out);
static int select_file(SCARDHANDLE card, const SCARD_IO_REQUEST *pio, uint16_t file_id, uint16_t *sw_out);

static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
        if (i + 1 < len) printf(" ");
    }
}

static int debug_apdu_enabled(void) {
    const char *v = getenv("NTAG_DEBUG_APDU");
    return v && v[0] != '\0' && v[0] != '0';
}

static LONG transmit(SCARDHANDLE card, const SCARD_IO_REQUEST *pioSendPci,
                     const uint8_t *apdu, size_t apdu_len,
                     uint8_t *resp, size_t *resp_len,
                     uint16_t *sw) {
    DWORD rlen = (DWORD)*resp_len;
    LONG rc = SCardTransmit(card, pioSendPci, apdu, (DWORD)apdu_len, NULL, resp, &rlen);
    if (rc != SCARD_S_SUCCESS) return rc;
    if (rlen < 2) return SCARD_E_PROTO_MISMATCH;
    *sw = (uint16_t)((resp[rlen - 2] << 8) | resp[rlen - 1]);
    *resp_len = rlen - 2;
    return SCARD_S_SUCCESS;
}

static int sw_ok(uint16_t sw) {
    return sw == 0x9000 || sw == 0x9100;
}

static int aes_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    size_t out_len = 0;
    CCCryptorStatus st = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionECBMode,
                                 key, 16, NULL, in, 16, out, 16, &out_len);
    return (st == kCCSuccess && out_len == 16);
}

static int aes_cbc_crypt(int encrypt, const uint8_t key[16], const uint8_t iv[16],
                         const uint8_t *in, size_t in_len, uint8_t *out) {
    size_t out_len = 0;
    CCCryptorStatus st = CCCrypt(encrypt ? kCCEncrypt : kCCDecrypt,
                                 kCCAlgorithmAES128, 0,
                                 key, 16, iv,
                                 in, in_len, out, in_len, &out_len);
    return (st == kCCSuccess && out_len == in_len);
}

static void xor_block(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) out[i] = a[i] ^ b[i];
}

static void left_shift_1bit(uint8_t *out, const uint8_t *in) {
    uint8_t carry = 0;
    for (int i = 15; i >= 0; i--) {
        uint8_t new_carry = (in[i] & 0x80) ? 1 : 0;
        out[i] = (uint8_t)((in[i] << 1) | carry);
        carry = new_carry;
    }
}

static void generate_cmac_subkeys(const uint8_t key[16], uint8_t k1[16], uint8_t k2[16]) {
    uint8_t L[16];
    uint8_t zero[16] = {0};
    aes_ecb_encrypt(key, zero, L);
    left_shift_1bit(k1, L);
    if (L[0] & 0x80) {
        k1[15] ^= 0x87;
    }
    left_shift_1bit(k2, k1);
    if (k1[0] & 0x80) {
        k2[15] ^= 0x87;
    }
}

static int aes_cmac(const uint8_t key[16], const uint8_t *msg, size_t msg_len, uint8_t out[16]) {
    uint8_t k1[16], k2[16];
    generate_cmac_subkeys(key, k1, k2);

    size_t n = (msg_len + 15) / 16;
    if (n == 0) n = 1;
    int last_complete = (msg_len != 0 && (msg_len % 16) == 0);

    uint8_t last_block[16];
    memset(last_block, 0, sizeof(last_block));

    if (last_complete) {
        const uint8_t *last = msg + 16 * (n - 1);
        xor_block(last_block, last, k1, 16);
    } else {
        size_t last_len = msg_len - 16 * (n - 1);
        if (msg_len == 0) last_len = 0;
        if (last_len > 0) memcpy(last_block, msg + 16 * (n - 1), last_len);
        last_block[last_len] = 0x80;
        xor_block(last_block, last_block, k2, 16);
    }

    uint8_t x[16] = {0};
    uint8_t y[16];
    for (size_t i = 0; i + 1 < n; i++) {
        xor_block(y, x, msg + 16 * i, 16);
        if (!aes_ecb_encrypt(key, y, x)) return 0;
    }

    xor_block(y, x, last_block, 16);
    if (!aes_ecb_encrypt(key, y, out)) return 0;
    return 1;
}

static void cmac_truncate_8(const uint8_t cmac[16], uint8_t out[8]) {
    // Take odd-indexed bytes 1,3,5,...,15 in order.
    for (int i = 0; i < 8; i++) out[i] = cmac[1 + i * 2];
}

static size_t pad_iso9797_m2(const uint8_t *in, size_t in_len, uint8_t *out) {
    size_t pad_len = 16 - (in_len % 16);
    if (pad_len == 0) pad_len = 16;
    memcpy(out, in, in_len);
    out[in_len] = 0x80;
    memset(out + in_len + 1, 0, pad_len - 1);
    return in_len + pad_len;
}

static size_t unpad_iso9797_m2(uint8_t *buf, size_t len) {
    if (len == 0) return 0;
    ssize_t i = (ssize_t)len - 1;
    while (i >= 0 && buf[i] == 0x00) i--;
    if (i >= 0 && buf[i] == 0x80) {
        return (size_t)i;
    }
    return len;
}

static void rotate_left_1(uint8_t *out, const uint8_t *in, size_t len) {
    if (len == 0) return;
    memmove(out, in + 1, len - 1);
    out[len - 1] = in[0];
}

static void rotate_right_1(uint8_t *out, const uint8_t *in, size_t len) {
    if (len == 0) return;
    memmove(out + 1, in, len - 1);
    out[0] = in[len - 1];
}

static void random_bytes(uint8_t *buf, size_t len) {
#if defined(__APPLE__)
    arc4random_buf(buf, len);
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(buf, 1, len, f);
        fclose(f);
    } else {
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)rand();
    }
#endif
}

static int parse_hex_key(const char *hex, uint8_t key[16]) {
    if (strlen(hex) != 32) return 0;
    for (int i = 0; i < 16; i++) {
        unsigned int val = 0;
        if (sscanf(hex + (i * 2), "%2x", &val) != 1) return 0;
        key[i] = (uint8_t)val;
    }
    return 1;
}

static void trim_whitespace(char *s) {
    if (!s) return;
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[--len] = '\0';
    }
    size_t start = 0;
    while (s[start] && isspace((unsigned char)s[start])) start++;
    if (start > 0) memmove(s, s + start, len - start + 1);
}

static int read_key_file(const char *path, uint8_t key[16]) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        trim_whitespace(line);
        if (line[0] == '\0') continue;
        fclose(f);
        return parse_hex_key(line, key);
    }
    fclose(f);
    return 0;
}

static int find_substr(const uint8_t *buf, size_t len, const char *needle, size_t *pos_out) {
    size_t nlen = strlen(needle);
    if (nlen == 0 || nlen > len) return 0;
    for (size_t i = 0; i + nlen <= len; i++) {
        if (memcmp(buf + i, needle, nlen) == 0) {
            *pos_out = i;
            return 1;
        }
    }
    return 0;
}

static int build_sdm_ndef(const char *base_url, sdm_ndef_t *out) {
    if (!base_url || !out) return 0;
    memset(out, 0, sizeof(*out));

    const char *uid_placeholder = "00000000000000";
    const char *ctr_placeholder = "000000";
    const char *mac_placeholder = "0000000000000000";

    int n = snprintf(out->url, sizeof(out->url), "%s?uid=%s&ctr=%s&mac=%s",
                     base_url, uid_placeholder, ctr_placeholder, mac_placeholder);
    if (n <= 0 || (size_t)n >= sizeof(out->url)) return 0;

    struct {
        const char *prefix;
        uint8_t code;
    } prefixes[] = {
        {"https://www.", 0x02},
        {"http://www.", 0x01},
        {"https://", 0x04},
        {"http://", 0x03},
    };

    uint8_t prefix_code = 0x00;
    const char *uri = out->url;
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        size_t plen = strlen(prefixes[i].prefix);
        if (strncmp(out->url, prefixes[i].prefix, plen) == 0) {
            prefix_code = prefixes[i].code;
            uri = out->url + plen;
            break;
        }
    }

    size_t uri_len = strlen(uri);
    if (uri_len > 255) return 0;
    size_t payload_len = 1 + uri_len;
    if (payload_len > 255) return 0;

    size_t record_len = 4 + payload_len;
    size_t total_len = 2 + record_len;
    if (total_len > 256) return 0;

    uint8_t *ndef = (uint8_t *)calloc(total_len, 1);
    if (!ndef) return 0;

    ndef[0] = (uint8_t)((record_len >> 8) & 0xFF);
    ndef[1] = (uint8_t)(record_len & 0xFF);
    ndef[2] = 0xD1;           // MB=1, ME=1, SR=1, TNF=0x01
    ndef[3] = 0x01;           // Type length
    ndef[4] = (uint8_t)payload_len;
    ndef[5] = 0x55;           // 'U'
    ndef[6] = prefix_code;    // URI prefix code
    memcpy(ndef + 7, uri, uri_len);

    size_t uid_key_pos = 0, ctr_key_pos = 0, mac_key_pos = 0;
    if (!find_substr(ndef, total_len, "uid=", &uid_key_pos) ||
        !find_substr(ndef, total_len, "ctr=", &ctr_key_pos) ||
        !find_substr(ndef, total_len, "mac=", &mac_key_pos)) {
        free(ndef);
        return 0;
    }

    size_t uid_offset = uid_key_pos + 4;
    size_t ctr_offset = ctr_key_pos + 4;
    size_t mac_offset = mac_key_pos + 4;

    if (uid_offset + SDM_UID_LEN_ASCII > total_len ||
        ctr_offset + SDM_CTR_LEN_ASCII > total_len ||
        mac_offset + SDM_MAC_LEN_ASCII > total_len) {
        free(ndef);
        return 0;
    }

    for (size_t i = 0; i < SDM_UID_LEN_ASCII; i++) {
        if (ndef[uid_offset + i] != '0') {
            free(ndef);
            return 0;
        }
    }
    for (size_t i = 0; i < SDM_CTR_LEN_ASCII; i++) {
        if (ndef[ctr_offset + i] != '0') {
            free(ndef);
            return 0;
        }
    }
    for (size_t i = 0; i < SDM_MAC_LEN_ASCII; i++) {
        if (ndef[mac_offset + i] != '0') {
            free(ndef);
            return 0;
        }
    }

    out->ndef = ndef;
    out->ndef_len = total_len;
    out->uid_offset = (uint32_t)uid_offset;
    out->ctr_offset = (uint32_t)ctr_offset;
    out->mac_input_offset = (uint32_t)uid_key_pos; // start at "uid="
    out->mac_offset = (uint32_t)mac_offset;        // start of MAC value
    return 1;
}

static int write_ndef_file_plain(SCARDHANDLE card, const SCARD_IO_REQUEST *pio,
                                 const uint8_t *data, size_t len, uint16_t *sw_out) {
    uint16_t sw = 0;
    if (!select_ndef_app(card, pio, &sw)) {
        if (sw_out) *sw_out = sw;
        return 0;
    }
    if (!select_file(card, pio, 0xE104, &sw)) {
        if (sw_out) *sw_out = sw;
        return 0;
    }

    size_t offset = 0;
    while (offset < len) {
        size_t chunk = len - offset;
        if (chunk > 0xFF) chunk = 0xFF;
        uint8_t apdu[MAX_APDU];
        size_t apdu_len = 0;
        apdu[apdu_len++] = 0x00;
        apdu[apdu_len++] = 0xD6; // Update Binary
        apdu[apdu_len++] = (uint8_t)((offset >> 8) & 0xFF);
        apdu[apdu_len++] = (uint8_t)(offset & 0xFF);
        apdu[apdu_len++] = (uint8_t)chunk;
        memcpy(apdu + apdu_len, data + offset, chunk);
        apdu_len += chunk;

        uint8_t resp[MAX_APDU];
        size_t rlen = sizeof(resp);
        if (transmit(card, pio, apdu, apdu_len, resp, &rlen, &sw) != SCARD_S_SUCCESS ||
            !sw_ok(sw)) {
            if (sw_out) *sw_out = sw;
            return 0;
        }
        offset += chunk;
    }

    if (sw_out) *sw_out = 0x9000;
    return 1;
}

static uint32_t read_u24_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}

static void write_u24_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
}

static uint32_t crc32_ieee(const uint8_t *data, size_t len) {
    // CRC32 as used by NTAG 424 DNA for ChangeKey: init=0xFFFFFFFF, reflected, no final xor.
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320u;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc;
}

static int write_key_hex_file(const char *path, const uint8_t key[16]) {
    FILE *f = fopen(path, "w");
    if (!f) return 0;
    for (int i = 0; i < 16; i++) fprintf(f, "%02X", key[i]);
    fprintf(f, "\n");
    fclose(f);
    return 1;
}

static int get_uid(SCARDHANDLE card, const SCARD_IO_REQUEST *pio, uint8_t *uid, size_t *uid_len) {
    uint8_t apdu[] = {0xFF, 0xCA, 0x00, 0x00, 0x00};
    uint8_t resp[MAX_APDU];
    size_t rlen = sizeof(resp);
    uint16_t sw = 0;
    LONG rc = transmit(card, pio, apdu, sizeof(apdu), resp, &rlen, &sw);
    if (rc != SCARD_S_SUCCESS || !sw_ok(sw) || rlen == 0) return 0;
    memcpy(uid, resp, rlen);
    *uid_len = rlen;
    return 1;
}

static int get_ats(SCARDHANDLE card, const SCARD_IO_REQUEST *pio, uint8_t *ats, size_t *ats_len) {
    uint8_t apdu[] = {0xFF, 0xCA, 0x01, 0x00, 0x00};
    uint8_t resp[MAX_APDU];
    size_t rlen = sizeof(resp);
    uint16_t sw = 0;
    LONG rc = transmit(card, pio, apdu, sizeof(apdu), resp, &rlen, &sw);
    if (rc != SCARD_S_SUCCESS || !sw_ok(sw) || rlen == 0) return 0;
    memcpy(ats, resp, rlen);
    *ats_len = rlen;
    return 1;
}

static int select_ndef_app(SCARDHANDLE card, const SCARD_IO_REQUEST *pio, uint16_t *sw_out) {
    uint8_t aid[] = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
    uint8_t apdu[5 + sizeof(aid) + 1];
    size_t apdu_len = 0;
    apdu[apdu_len++] = 0x00;
    apdu[apdu_len++] = 0xA4;
    apdu[apdu_len++] = 0x04;
    apdu[apdu_len++] = 0x00;
    apdu[apdu_len++] = (uint8_t)sizeof(aid);
    memcpy(apdu + apdu_len, aid, sizeof(aid));
    apdu_len += sizeof(aid);
    apdu[apdu_len++] = 0x00;

    uint8_t resp[MAX_APDU];
    size_t rlen = sizeof(resp);
    uint16_t sw = 0;
    LONG rc = transmit(card, pio, apdu, apdu_len, resp, &rlen, &sw);
    if (sw_out) *sw_out = sw;
    if (rc != SCARD_S_SUCCESS) return 0;
    return sw_ok(sw);
}

static int select_file(SCARDHANDLE card, const SCARD_IO_REQUEST *pio, uint16_t file_id, uint16_t *sw_out) {
    uint8_t apdu[] = {0x00, 0xA4, 0x00, 0x0C, 0x02,
                      (uint8_t)((file_id >> 8) & 0xFF), (uint8_t)(file_id & 0xFF)};
    uint8_t resp[MAX_APDU];
    size_t rlen = sizeof(resp);
    uint16_t sw = 0;
    LONG rc = transmit(card, pio, apdu, sizeof(apdu), resp, &rlen, &sw);
    if (sw_out) *sw_out = sw;
    if (rc != SCARD_S_SUCCESS) return 0;
    return sw_ok(sw);
}

static int read_binary(SCARDHANDLE card, const SCARD_IO_REQUEST *pio,
                       uint16_t offset, uint8_t le,
                       uint8_t *out, size_t *out_len, uint16_t *sw_out) {
    uint8_t apdu[] = {0x00, 0xB0, (uint8_t)((offset >> 8) & 0xFF),
                      (uint8_t)(offset & 0xFF), le};
    uint8_t resp[MAX_APDU];
    size_t rlen = sizeof(resp);
    uint16_t sw = 0;
    LONG rc = transmit(card, pio, apdu, sizeof(apdu), resp, &rlen, &sw);
    if (rc != SCARD_S_SUCCESS) return 0;

    if ((sw & 0xFF00) == 0x6C00) {
        apdu[4] = (uint8_t)(sw & 0x00FF);
        rlen = sizeof(resp);
        rc = transmit(card, pio, apdu, sizeof(apdu), resp, &rlen, &sw);
        if (rc != SCARD_S_SUCCESS) return 0;
    }

    if (sw_out) *sw_out = sw;
    if (!sw_ok(sw)) return 0;
    memcpy(out, resp, rlen);
    *out_len = rlen;
    return 1;
}

static int authenticate_ev2_first(SCARDHANDLE card, const SCARD_IO_REQUEST *pio,
                                  const uint8_t key[16], uint8_t key_no,
                                  ssm_session_t *sess) {
    uint8_t apdu[MAX_APDU];
    uint8_t resp[MAX_APDU];
    size_t rlen;
    uint16_t sw = 0;

    // Part 1: 90 71 00 00 02 KeyNo LenCap 00 (LenCap=0)
    apdu[0] = 0x90;
    apdu[1] = 0x71;
    apdu[2] = 0x00;
    apdu[3] = 0x00;
    apdu[4] = 0x02;
    apdu[5] = key_no;
    apdu[6] = 0x00; // LenCap = 0
    apdu[7] = 0x00;

    rlen = sizeof(resp);
    if (transmit(card, pio, apdu, 8, resp, &rlen, &sw) != SCARD_S_SUCCESS) return 0;
    if (sw != 0x91AF || rlen != 16) return 0;

    uint8_t rndB_enc[16];
    memcpy(rndB_enc, resp, 16);
    uint8_t rndB[16];
    uint8_t iv0[16] = {0};
    if (!aes_cbc_crypt(0, key, iv0, rndB_enc, 16, rndB)) return 0;

    uint8_t rndA[16];
    const char *rndA_hex = getenv("NTAG_RNDA");
    if (rndA_hex && strlen(rndA_hex) == 32) {
        if (!parse_hex_key(rndA_hex, rndA)) {
            random_bytes(rndA, 16);
        }
    } else {
        random_bytes(rndA, 16);
    }

    uint8_t rndB_rot[16];
    rotate_left_1(rndB_rot, rndB, 16);

    uint8_t rndAB[32];
    memcpy(rndAB, rndA, 16);
    memcpy(rndAB + 16, rndB_rot, 16);

    uint8_t rndAB_enc[32];
    if (!aes_cbc_crypt(1, key, iv0, rndAB, 32, rndAB_enc)) return 0;

    // Part 2: 90 AF 00 00 20 <RndA||RndB'> 00
    apdu[0] = 0x90;
    apdu[1] = 0xAF;
    apdu[2] = 0x00;
    apdu[3] = 0x00;
    apdu[4] = 0x20;
    memcpy(apdu + 5, rndAB_enc, 32);
    apdu[37] = 0x00;

    rlen = sizeof(resp);
    if (transmit(card, pio, apdu, 38, resp, &rlen, &sw) != SCARD_S_SUCCESS) return 0;
    if (sw != 0x9100 || rlen != 32) return 0;

    uint8_t dec[32];
    if (!aes_cbc_crypt(0, key, iv0, resp, 32, dec)) return 0;

    uint8_t ti[4];
    memcpy(ti, dec, 4);

    uint8_t rndA_rot[16];
    memcpy(rndA_rot, dec + 4, 16);

    uint8_t rndA_check[16];
    rotate_right_1(rndA_check, rndA_rot, 16);
    if (memcmp(rndA_check, rndA, 16) != 0) return 0;

    // Build SV1 and SV2 (32-byte messages)
    uint8_t sv1[32];
    uint8_t sv2[32];
    uint8_t prefix1[6] = {0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80};
    uint8_t prefix2[6] = {0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80};

    memcpy(sv1, prefix1, 6);
    memcpy(sv2, prefix2, 6);

    // RndA[15:14] -> first two bytes, RndA[13:8] -> next 6 bytes
    memcpy(sv1 + 6, rndA, 2);
    memcpy(sv2 + 6, rndA, 2);

    uint8_t xor_part[6];
    for (int i = 0; i < 6; i++) {
        xor_part[i] = rndA[2 + i] ^ rndB[i];
    }
    memcpy(sv1 + 8, xor_part, 6);
    memcpy(sv2 + 8, xor_part, 6);

    // RndB[9:0] -> bytes 6..15 (10 bytes)
    memcpy(sv1 + 14, rndB + 6, 10);
    memcpy(sv2 + 14, rndB + 6, 10);

    // RndA[7:0] -> bytes 8..15 (8 bytes)
    memcpy(sv1 + 24, rndA + 8, 8);
    memcpy(sv2 + 24, rndA + 8, 8);

    if (!aes_cmac(key, sv1, sizeof(sv1), sess->kenc)) return 0;
    if (!aes_cmac(key, sv2, sizeof(sv2), sess->kmac)) return 0;
    memcpy(sess->ti, ti, 4);
    sess->cmd_ctr = 0;
    sess->key_no = key_no;
    sess->authenticated = 1;

    const char *dbg_keys = getenv("NTAG_DEBUG_KEYS");
    if (dbg_keys && *dbg_keys) {
        printf("RndA: ");
        print_hex(rndA, 16);
        printf("\nRndB: ");
        print_hex(rndB, 16);
        printf("\nTI: ");
        print_hex(ti, 4);
        printf("\nKenc: ");
        print_hex(sess->kenc, 16);
        printf("\nKmac: ");
        print_hex(sess->kmac, 16);
        printf("\n");
    }
    return 1;
}

static int ssm_cmd_full(SCARDHANDLE card, const SCARD_IO_REQUEST *pio, ssm_session_t *sess,
                        uint8_t cmd, const uint8_t *cmd_header, size_t cmd_header_len,
                        const uint8_t *cmd_data, size_t cmd_data_len,
                        uint8_t *out, size_t *out_len, uint16_t *sw_out) {
    if (!sess || !sess->authenticated) return 0;

    uint8_t ivc_in[16] = {0};
    ivc_in[0] = 0xA5;
    ivc_in[1] = 0x5A;
    memcpy(ivc_in + 2, sess->ti, 4);
    ivc_in[6] = (uint8_t)(sess->cmd_ctr & 0xFF);
    ivc_in[7] = (uint8_t)((sess->cmd_ctr >> 8) & 0xFF);
    uint8_t ivc[16];
    if (!aes_ecb_encrypt(sess->kenc, ivc_in, ivc)) return 0;

    uint8_t enc_data[MAX_APDU];
    size_t enc_len = 0;
    if (cmd_data_len > 0) {
        uint8_t padded[MAX_APDU];
        size_t padded_len = pad_iso9797_m2(cmd_data, cmd_data_len, padded);
        if (padded_len > sizeof(enc_data)) return 0;
        if (!aes_cbc_crypt(1, sess->kenc, ivc, padded, padded_len, enc_data)) return 0;
        enc_len = padded_len;
    }

    uint8_t mac_input[MAX_APDU];
    size_t mac_len = 0;
    mac_input[mac_len++] = cmd;
    mac_input[mac_len++] = (uint8_t)(sess->cmd_ctr & 0xFF);
    mac_input[mac_len++] = (uint8_t)((sess->cmd_ctr >> 8) & 0xFF);
    memcpy(mac_input + mac_len, sess->ti, 4);
    mac_len += 4;
    if (cmd_header_len > 0) {
        memcpy(mac_input + mac_len, cmd_header, cmd_header_len);
        mac_len += cmd_header_len;
    }
    if (enc_len > 0) {
        memcpy(mac_input + mac_len, enc_data, enc_len);
        mac_len += enc_len;
    }

    uint8_t cmac[16];
    if (!aes_cmac(sess->kmac, mac_input, mac_len, cmac)) return 0;
    uint8_t mact[8];
    cmac_truncate_8(cmac, mact);

    uint8_t apdu[MAX_APDU];
    size_t apdu_len = 0;
    apdu[apdu_len++] = 0x90;
    apdu[apdu_len++] = cmd;
    apdu[apdu_len++] = 0x00;
    apdu[apdu_len++] = 0x00;

    size_t data_len = cmd_header_len + enc_len + sizeof(mact);
    if (data_len > 255) return 0;
    apdu[apdu_len++] = (uint8_t)data_len;
    if (cmd_header_len > 0) {
        memcpy(apdu + apdu_len, cmd_header, cmd_header_len);
        apdu_len += cmd_header_len;
    }
    if (enc_len > 0) {
        memcpy(apdu + apdu_len, enc_data, enc_len);
        apdu_len += enc_len;
    }
    memcpy(apdu + apdu_len, mact, sizeof(mact));
    apdu_len += sizeof(mact);
    apdu[apdu_len++] = 0x00;

    if (debug_apdu_enabled()) {
        printf("APDU cmd 0x%02X: ", cmd);
        print_hex(apdu, apdu_len);
        printf("\n");
    }

    uint8_t resp[MAX_APDU];
    size_t rlen = sizeof(resp);
    uint16_t sw = 0;
    if (transmit(card, pio, apdu, apdu_len, resp, &rlen, &sw) != SCARD_S_SUCCESS) return 0;
    if (sw_out) *sw_out = sw;
    if ((sw & 0xFF00) != 0x9100) return 0;
    if (rlen < 8) return 0;

    size_t resp_enc_len = rlen - 8;
    uint8_t *resp_enc = resp;
    uint8_t *resp_mact = resp + resp_enc_len;

    uint8_t ivr_in[16] = {0};
    ivr_in[0] = 0x5A;
    ivr_in[1] = 0xA5;
    memcpy(ivr_in + 2, sess->ti, 4);
    uint16_t cmdctr1 = (uint16_t)(sess->cmd_ctr + 1);
    ivr_in[6] = (uint8_t)(cmdctr1 & 0xFF);
    ivr_in[7] = (uint8_t)((cmdctr1 >> 8) & 0xFF);
    uint8_t ivr[16];
    if (!aes_ecb_encrypt(sess->kenc, ivr_in, ivr)) return 0;

    uint8_t mac_in2[MAX_APDU];
    size_t mac2_len = 0;
    mac_in2[mac2_len++] = (uint8_t)(sw & 0x00FF); // SW2
    mac_in2[mac2_len++] = (uint8_t)(cmdctr1 & 0xFF);
    mac_in2[mac2_len++] = (uint8_t)((cmdctr1 >> 8) & 0xFF);
    memcpy(mac_in2 + mac2_len, sess->ti, 4);
    mac2_len += 4;
    if (resp_enc_len > 0) {
        memcpy(mac_in2 + mac2_len, resp_enc, resp_enc_len);
        mac2_len += resp_enc_len;
    }

    uint8_t cmac2[16];
    if (!aes_cmac(sess->kmac, mac_in2, mac2_len, cmac2)) return 0;
    uint8_t mact2[8];
    cmac_truncate_8(cmac2, mact2);
    if (memcmp(resp_mact, mact2, 8) != 0) return 0;

    size_t out_written = 0;
    if (resp_enc_len > 0) {
        uint8_t dec[MAX_APDU];
        if (!aes_cbc_crypt(0, sess->kenc, ivr, resp_enc, resp_enc_len, dec)) return 0;
        out_written = unpad_iso9797_m2(dec, resp_enc_len);
        if (out_written > *out_len) return 0;
        memcpy(out, dec, out_written);
    }

    *out_len = out_written;
    sess->cmd_ctr = cmdctr1;
    return 1;
}

static int get_file_settings_plain(SCARDHANDLE card, const SCARD_IO_REQUEST *pio,
                                   uint8_t file_no, uint8_t *out, size_t *out_len,
                                   uint16_t *sw_out) {
    uint8_t apdu[] = {0x90, 0xF5, 0x00, 0x00, 0x01, file_no, 0x00};
    uint8_t resp[MAX_APDU];
    size_t rlen = sizeof(resp);
    uint16_t sw = 0;
    LONG rc = transmit(card, pio, apdu, sizeof(apdu), resp, &rlen, &sw);
    if (sw_out) *sw_out = sw;
    if (rc != SCARD_S_SUCCESS || !sw_ok(sw)) return 0;
    if (rlen > *out_len) return 0;
    memcpy(out, resp, rlen);
    *out_len = rlen;
    return 1;
}

static int get_file_settings_secure(SCARDHANDLE card, const SCARD_IO_REQUEST *pio,
                                    ssm_session_t *sess, uint8_t file_no,
                                    uint8_t *out, size_t *out_len, uint16_t *sw_out) {
    uint8_t header = file_no;
    return ssm_cmd_full(card, pio, sess, 0xF5, &header, 1, NULL, 0, out, out_len, sw_out);
}

static int parse_file_settings(const uint8_t *data, size_t len, file_settings_info_t *info) {
    if (info) memset(info, 0, sizeof(*info));
    if (len < 7) return 0;

    uint8_t file_type = data[0];
    uint8_t file_option = data[1];
    uint8_t ar1 = data[2];
    uint8_t ar2 = data[3];
    uint32_t file_size = read_u24_le(&data[4]);

    printf("FileSettings:\n");
    printf("  FileType: 0x%02X\n", file_type);
    printf("  FileOption: 0x%02X (SDM=%s, CommMode=%u)\n",
           file_option, (file_option & 0x40) ? "on" : "off", (file_option & 0x03));
    printf("  AccessRights: %02X %02X (RW=%X, CAR=%X, R=%X, W=%X)\n",
           ar1, ar2, (ar1 >> 4) & 0x0F, ar1 & 0x0F, (ar2 >> 4) & 0x0F, ar2 & 0x0F);
    printf("  FileSize: %u bytes\n", file_size);

    if (info) {
        info->valid = 1;
        info->file_option = file_option;
        info->file_size = file_size;
        info->sdm_enabled = (file_option & 0x40) ? 1 : 0;
        info->ar1 = ar1;
        info->ar2 = ar2;
    }

    size_t idx = 7;
    if (!(file_option & 0x40)) return 1;

    if (len < idx + 3) return 0;
    uint8_t sdm_options = data[idx++];
    uint8_t sdm_ar_lsb = data[idx++];
    uint8_t sdm_ar_msb = data[idx++];
    uint16_t sdm_ar = (uint16_t)(sdm_ar_lsb | (sdm_ar_msb << 8));
    uint8_t sdm_meta = (uint8_t)((sdm_ar >> 12) & 0x0F);
    uint8_t sdm_file = (uint8_t)((sdm_ar >> 8) & 0x0F);
    uint8_t sdm_rfu = (uint8_t)((sdm_ar >> 4) & 0x0F);
    uint8_t sdm_ctr = (uint8_t)(sdm_ar & 0x0F);

    printf("  SDMOptions: 0x%02X (UID=%s, ReadCtr=%s, EncFile=%s, ASCII=%s)\n",
           sdm_options,
           (sdm_options & 0x80) ? "on" : "off",
           (sdm_options & 0x40) ? "on" : "off",
           (sdm_options & 0x10) ? "on" : "off",
           (sdm_options & 0x01) ? "on" : "off");
    printf("  SDMAccessRights: 0x%04X (Meta=%X, File=%X, CtrRet=%X, RFU=%X)\n",
           sdm_ar, sdm_meta, sdm_file, sdm_ctr, sdm_rfu);

    if (info) {
        info->sdm_options = sdm_options;
        info->sdm_meta_read = sdm_meta;
        info->sdm_file_read = sdm_file;
        info->sdm_ctr_ret = sdm_ctr;
        info->sdm_read_ctr_enabled = (sdm_options & 0x40) ? 1 : 0;
    }

    if ((sdm_options & 0x80) && sdm_meta == 0x0E) {
        if (len < idx + 3) return 0;
        uint32_t uid_offset = read_u24_le(&data[idx]);
        idx += 3;
        printf("  UIDOffset: 0x%06X\n", uid_offset);
    }

    if ((sdm_options & 0x40) && sdm_meta == 0x0E) {
        if (len < idx + 3) return 0;
        uint32_t ctr_offset = read_u24_le(&data[idx]);
        idx += 3;
        if (ctr_offset == 0xFFFFFF) {
            printf("  SDMReadCtrOffset: none (0xFFFFFF)\n");
        } else {
            printf("  SDMReadCtrOffset: 0x%06X\n", ctr_offset);
        }
    }

    if (sdm_meta <= 0x04) {
        if (len < idx + 3) return 0;
        uint32_t picc_offset = read_u24_le(&data[idx]);
        idx += 3;
        printf("  PICCDataOffset: 0x%06X\n", picc_offset);
    }

    if (sdm_file != 0x0F) {
        if (len < idx + 3) return 0;
        uint32_t mac_input_offset = read_u24_le(&data[idx]);
        idx += 3;
        printf("  SDMMACInputOffset: 0x%06X\n", mac_input_offset);
    }

    if (sdm_file != 0x0F && (sdm_options & 0x10)) {
        if (len < idx + 6) return 0;
        uint32_t enc_offset = read_u24_le(&data[idx]);
        idx += 3;
        uint32_t enc_len = read_u24_le(&data[idx]);
        idx += 3;
        printf("  SDMENCOffset: 0x%06X\n", enc_offset);
        printf("  SDMENCLength: 0x%06X\n", enc_len);
    }

    if (sdm_file != 0x0F) {
        if (len < idx + 3) return 0;
        uint32_t mac_offset = read_u24_le(&data[idx]);
        idx += 3;
        printf("  SDMMACOffset: 0x%06X\n", mac_offset);
    }

    if (sdm_options & 0x20) {
        if (len < idx + 3) return 0;
        uint32_t ctr_limit = read_u24_le(&data[idx]);
        idx += 3;
        printf("  SDMReadCtrLimit: 0x%06X\n", ctr_limit);
    }

    return 1;
}

static int change_key(SCARDHANDLE card, const SCARD_IO_REQUEST *pio, ssm_session_t *sess,
                      uint8_t key_no, const uint8_t old_key[16], const uint8_t new_key[16],
                      uint8_t key_ver, uint16_t *sw_out) {
    uint8_t key_data[21];
    for (int i = 0; i < 16; i++) key_data[i] = new_key[i] ^ old_key[i];
    key_data[16] = key_ver;
    uint32_t crc = crc32_ieee(new_key, 16);
    key_data[17] = (uint8_t)(crc & 0xFF);
    key_data[18] = (uint8_t)((crc >> 8) & 0xFF);
    key_data[19] = (uint8_t)((crc >> 16) & 0xFF);
    key_data[20] = (uint8_t)((crc >> 24) & 0xFF);

    uint8_t header = key_no;
    uint8_t resp[16];
    size_t resp_len = sizeof(resp);
    return ssm_cmd_full(card, pio, sess, 0xC4, &header, 1, key_data, sizeof(key_data),
                        resp, &resp_len, sw_out);
}

static int change_file_settings_sdm(SCARDHANDLE card, const SCARD_IO_REQUEST *pio, ssm_session_t *sess,
                                    uint8_t file_no, uint8_t comm_mode,
                                    uint8_t ar1, uint8_t ar2,
                                    uint8_t sdm_options,
                                    uint8_t sdm_meta, uint8_t sdm_file, uint8_t sdm_ctr,
                                    uint32_t uid_offset,
                                    uint32_t sdm_read_ctr_offset,
                                    uint32_t sdm_mac_input_offset,
                                    uint32_t sdm_mac_offset,
                                    uint16_t *sw_out) {
    uint8_t data[64];
    size_t len = 0;

    uint8_t file_option = (uint8_t)((comm_mode & 0x03) | 0x40); // enable SDM/mirroring
    data[len++] = file_option;
    data[len++] = ar1;
    data[len++] = ar2;
    data[len++] = sdm_options;

    uint16_t sdm_ar = (uint16_t)(((sdm_meta & 0x0F) << 12) |
                                 ((sdm_file & 0x0F) << 8) |
                                 (0x0F << 4) |
                                 (sdm_ctr & 0x0F));
    data[len++] = (uint8_t)(sdm_ar & 0xFF);       // LSB first
    data[len++] = (uint8_t)((sdm_ar >> 8) & 0xFF);

    if ((sdm_options & 0x80) && sdm_meta == 0x0E) {
        write_u24_le(&data[len], uid_offset);
        len += 3;
    }

    if ((sdm_options & 0x40) && sdm_meta == 0x0E) {
        write_u24_le(&data[len], sdm_read_ctr_offset);
        len += 3;
    }

    if (sdm_file != 0x0F) {
        write_u24_le(&data[len], sdm_mac_input_offset);
        len += 3;
    }

    if (sdm_file != 0x0F) {
        write_u24_le(&data[len], sdm_mac_offset);
        len += 3;
    }

    uint8_t header = file_no;
    uint8_t resp[16];
    size_t resp_len = sizeof(resp);
    return ssm_cmd_full(card, pio, sess, 0x5F, &header, 1, data, len, resp, &resp_len, sw_out);
}

static int get_sdm_read_counter(SCARDHANDLE card, const SCARD_IO_REQUEST *pio,
                                uint8_t file_no, uint32_t *counter, uint16_t *sw_out) {
    uint8_t apdu[] = {0x90, 0xF6, 0x00, 0x00, 0x01, file_no, 0x00};
    uint8_t resp[MAX_APDU];
    size_t rlen = sizeof(resp);
    uint16_t sw = 0;
    LONG rc = transmit(card, pio, apdu, sizeof(apdu), resp, &rlen, &sw);
    if (sw_out) *sw_out = sw;
    if (rc != SCARD_S_SUCCESS || !sw_ok(sw) || rlen < 3) return 0;
    *counter = (uint32_t)resp[0] | ((uint32_t)resp[1] << 8) | ((uint32_t)resp[2] << 16);
    return 1;
}

int main(int argc, char **argv) {
    LONG rc;
    SCARDCONTEXT ctx;
    rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
    if (rc != SCARD_S_SUCCESS) {
        fprintf(stderr, "SCardEstablishContext failed: 0x%08lX\n", (unsigned long)rc);
        return 1;
    }

    DWORD readers_len = 0;
    rc = SCardListReaders(ctx, NULL, NULL, &readers_len);
    if (rc != SCARD_S_SUCCESS || readers_len == 0) {
        fprintf(stderr, "No PC/SC readers found.\n");
        SCardReleaseContext(ctx);
        return 1;
    }

    char *readers = (char *)malloc(readers_len);
    if (!readers) {
        fprintf(stderr, "Out of memory.\n");
        SCardReleaseContext(ctx);
        return 1;
    }

    rc = SCardListReaders(ctx, NULL, readers, &readers_len);
    if (rc != SCARD_S_SUCCESS || readers[0] == '\0') {
        fprintf(stderr, "No PC/SC readers found.\n");
        free(readers);
        SCardReleaseContext(ctx);
        return 1;
    }

    int index = 0;
    uint8_t key[16] = {0};
    uint8_t key_no = 0x00;
    uint8_t counter_file_no = 0x02;
    int do_provision = 0;
    uint8_t new_key_no = 0x01;
    const char *key_out_path = NULL;
    const char *provision_key_path = NULL;
    int do_sdm_setup = 0;
    uint8_t sdm_key_no = 0x01;
    const char *sdm_base_url = "https://example.com/tap";
    int do_rotate_key = 0;
    uint8_t rotate_key_no = 0x01;
    const char *rotate_old_key_path = NULL;
    const char *rotate_new_key_in_path = NULL;
    const char *rotate_new_key_path = NULL;

    int argi = 1;
    if (argi < argc && argv[argi][0] != '-') {
        index = atoi(argv[argi++]);
    }
    if (argi < argc && argv[argi][0] != '-') {
        if (!parse_hex_key(argv[argi], key)) {
            fprintf(stderr, "Key must be 32 hex chars (AES-128), e.g. 000000... \n");
            return 2;
        }
        argi++;
    }
    if (argi < argc && argv[argi][0] != '-') {
        key_no = (uint8_t)strtoul(argv[argi++], NULL, 0);
    }
    if (argi < argc && argv[argi][0] != '-') {
        counter_file_no = (uint8_t)strtoul(argv[argi++], NULL, 0);
    }
    for (; argi < argc; argi++) {
        if (strcmp(argv[argi], "--provision") == 0) {
            do_provision = 1;
        } else if (strcmp(argv[argi], "--provision-key") == 0 && argi + 1 < argc) {
            provision_key_path = argv[++argi];
        } else if (strcmp(argv[argi], "--new-keyno") == 0 && argi + 1 < argc) {
            new_key_no = (uint8_t)strtoul(argv[++argi], NULL, 0);
        } else if (strcmp(argv[argi], "--key-out") == 0 && argi + 1 < argc) {
            key_out_path = argv[++argi];
        } else if (strcmp(argv[argi], "--rotate-key") == 0) {
            do_rotate_key = 1;
        } else if (strcmp(argv[argi], "--rotate-keyno") == 0 && argi + 1 < argc) {
            rotate_key_no = (uint8_t)strtoul(argv[++argi], NULL, 0);
        } else if (strcmp(argv[argi], "--old-key") == 0 && argi + 1 < argc) {
            rotate_old_key_path = argv[++argi];
        } else if (strcmp(argv[argi], "--rotate-new-key") == 0 && argi + 1 < argc) {
            rotate_new_key_in_path = argv[++argi];
        } else if (strcmp(argv[argi], "--new-key-out") == 0 && argi + 1 < argc) {
            rotate_new_key_path = argv[++argi];
        } else if (strcmp(argv[argi], "--sdm-setup") == 0) {
            do_sdm_setup = 1;
        } else if (strcmp(argv[argi], "--sdm-url") == 0 && argi + 1 < argc) {
            sdm_base_url = argv[++argi];
        } else if (strcmp(argv[argi], "--sdm-keyno") == 0 && argi + 1 < argc) {
            sdm_key_no = (uint8_t)strtoul(argv[++argi], NULL, 0);
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[argi]);
            fprintf(stderr, "Usage: %s [reader_index] [auth_key_hex] [auth_key_no] [file_no] "
                            "[--provision] [--provision-key PATH] [--new-keyno N] [--key-out PATH] "
                            "[--rotate-key] [--rotate-keyno N] [--old-key PATH] [--rotate-new-key PATH] [--new-key-out PATH] "
                            "[--sdm-setup] [--sdm-url URL] [--sdm-keyno N]\n", argv[0]);
            return 2;
        }
    }
    if (do_provision && do_rotate_key) {
        fprintf(stderr, "Choose either --provision or --rotate-key (not both).\n");
        return 2;
    }

    char *p = readers;
    int i = 0;
    char *selected = NULL;
    while (*p) {
        if (i == index) {
            selected = p;
            break;
        }
        p += strlen(p) + 1;
        i++;
    }

    if (!selected) {
        fprintf(stderr, "Reader index out of range. Available: 0..%d\n", i - 1);
        free(readers);
        SCardReleaseContext(ctx);
        return 1;
    }

    printf("Using reader: %s\n", selected);

    SCARDHANDLE card;
    DWORD activeProtocol = 0;
    rc = SCardConnect(ctx, selected, SCARD_SHARE_SHARED,
                      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card, &activeProtocol);
    if (rc != SCARD_S_SUCCESS) {
        fprintf(stderr, "SCardConnect failed: 0x%08lX\n", (unsigned long)rc);
        free(readers);
        SCardReleaseContext(ctx);
        return 1;
    }

    SCARD_IO_REQUEST ioReq;
    if (activeProtocol == SCARD_PROTOCOL_T1) {
        ioReq = *SCARD_PCI_T1;
    } else {
        ioReq = *SCARD_PCI_T0;
    }

    uint8_t atr[64];
    DWORD atr_len = sizeof(atr);
    DWORD state = 0, proto = 0;
    char reader_name[256];
    DWORD rn_len = sizeof(reader_name);
    rc = SCardStatus(card, reader_name, &rn_len, &state, &proto, atr, &atr_len);
    if (rc == SCARD_S_SUCCESS) {
        printf("ATR: ");
        print_hex(atr, atr_len);
        printf("\n");
    }

    uint8_t uid[16];
    size_t uid_len = 0;
    if (get_uid(card, &ioReq, uid, &uid_len)) {
        printf("UID: ");
        print_hex(uid, uid_len);
        printf("\n");
    } else {
        printf("UID: (not available via GET DATA)\n");
    }

    uint8_t ats[32];
    size_t ats_len = 0;
    if (get_ats(card, &ioReq, ats, &ats_len)) {
        printf("ATS: ");
        print_hex(ats, ats_len);
        printf("\n");
    } else {
        printf("ATS: (not available via GET DATA)\n");
    }

    uint16_t sw = 0;
    if (!select_ndef_app(card, &ioReq, &sw)) {
        printf("NDEF: SELECT NDEF app failed (SW1SW2=%04X)\n", sw);
    } else if (!select_file(card, &ioReq, 0xE103, &sw)) {
        printf("NDEF: SELECT CC file failed (SW1SW2=%04X)\n", sw);
    } else {
        uint8_t cc[32];
        size_t cc_len = sizeof(cc);
        if (!read_binary(card, &ioReq, 0x0000, 0x0F, cc, &cc_len, &sw) || cc_len < 15) {
            printf("NDEF: READ CC failed (SW1SW2=%04X)\n", sw);
        } else {
            uint16_t cclen = (uint16_t)((cc[0] << 8) | cc[1]);
            uint8_t mapping = cc[2];
            uint16_t mle = (uint16_t)((cc[3] << 8) | cc[4]);
            uint16_t mlc = (uint16_t)((cc[5] << 8) | cc[6]);

            uint16_t ndef_file_id = 0xE104;
            uint16_t ndef_file_size = 0;
            uint8_t read_access = 0xFF;
            uint8_t write_access = 0xFF;
            if (cc[7] == 0x04 && cc[8] >= 6) {
                ndef_file_id = (uint16_t)((cc[9] << 8) | cc[10]);
                ndef_file_size = (uint16_t)((cc[11] << 8) | cc[12]);
                read_access = cc[13];
                write_access = cc[14];
            }

            if (!select_file(card, &ioReq, ndef_file_id, &sw)) {
                printf("NDEF: SELECT NDEF file failed (SW1SW2=%04X)\n", sw);
            } else {
                uint8_t nlen_bytes[4];
                size_t nlen_len = sizeof(nlen_bytes);
                if (!read_binary(card, &ioReq, 0x0000, 0x02, nlen_bytes, &nlen_len, &sw) || nlen_len < 2) {
                    printf("NDEF: READ NLEN failed (SW1SW2=%04X)\n", sw);
                } else {
                    uint16_t nlen = (uint16_t)((nlen_bytes[0] << 8) | nlen_bytes[1]);
                    uint8_t *ndef = (uint8_t *)calloc(nlen ? nlen : 1, 1);
                    uint16_t offset = 2;
                    uint16_t remaining = nlen;
                    size_t total = 0;
                    int ok = 1;
                    while (remaining > 0) {
                        uint8_t chunk = remaining > 0xFF ? 0xFF : (uint8_t)remaining;
                        uint8_t tmp[256];
                        size_t tmp_len = sizeof(tmp);
                        if (!read_binary(card, &ioReq, offset, chunk, tmp, &tmp_len, &sw)) {
                            ok = 0;
                            break;
                        }
                        memcpy(ndef + total, tmp, tmp_len);
                        total += tmp_len;
                        offset += (uint16_t)tmp_len;
                        remaining -= (uint16_t)tmp_len;
                    }

                    if (!ok) {
                        printf("NDEF: READ NDEF failed at offset %u (SW1SW2=%04X)\n", offset, sw);
                    } else {
                        printf("NDEF:\n");
                        printf("  CC length: 0x%04X\n", cclen);
                        printf("  Mapping version: 0x%02X\n", mapping);
                        printf("  MLe: 0x%04X\n", mle);
                        printf("  MLc: 0x%04X\n", mlc);
                        printf("  NDEF File ID: 0x%04X\n", ndef_file_id);
                        printf("  NDEF File Size: %u bytes\n", ndef_file_size);
                        printf("  Read Access: 0x%02X\n", read_access);
                        printf("  Write Access: 0x%02X\n", write_access);
                        printf("  NLEN: %u bytes\n", nlen);
                        printf("  NDEF (hex): ");
                        print_hex(ndef, total);
                        printf("\n");
                    }
                    free(ndef);
                }
            }
        }
    }

    file_settings_info_t fs_info;
    memset(&fs_info, 0, sizeof(fs_info));
    uint8_t fs_data[128];
    size_t fs_len = sizeof(fs_data);
    int fs_plain_failed = 0;
    uint16_t fs_plain_sw = 0;
    if (get_file_settings_plain(card, &ioReq, counter_file_no, fs_data, &fs_len, &sw)) {
        if (!parse_file_settings(fs_data, fs_len, &fs_info)) {
            printf("FileSettings: parse error\n");
        }
    } else {
        fs_plain_failed = 1;
        fs_plain_sw = sw;
        printf("FileSettings: GET failed (SW1SW2=%04X)\n", sw);
    }

    uint8_t counter_key[16];
    memcpy(counter_key, key, sizeof(counter_key));
    uint8_t counter_key_no = key_no;
    uint8_t new_key[16];
    int new_key_set = 0;
    char key_out_buf[64] = {0};

    if (do_provision) {
        if (new_key_no > 0x0F) {
            printf("Provisioning: new key number must be 0x00..0x0F\n");
            goto cleanup;
        }
        if (provision_key_path) {
            if (!read_key_file(provision_key_path, new_key)) {
                printf("Provisioning: failed to read key file: %s\n", provision_key_path);
                goto cleanup;
            }
            printf("Provisioning: using key from %s (KeyNo 0x%02X)\n", provision_key_path, new_key_no);
        } else {
            if (!key_out_path) {
                snprintf(key_out_buf, sizeof(key_out_buf), "ntag424_key%u.hex", new_key_no);
                key_out_path = key_out_buf;
            }
            random_bytes(new_key, sizeof(new_key));
            if (!write_key_hex_file(key_out_path, new_key)) {
                printf("Provisioning: failed to write key file: %s\n", key_out_path);
                goto cleanup;
            }
            printf("Provisioning: new key (KeyNo 0x%02X) written to %s\n", new_key_no, key_out_path);
        }

        ssm_session_t sess0;
        memset(&sess0, 0, sizeof(sess0));
        printf("Provisioning: authenticating with KeyNo 0x%02X for ChangeKey...\n", key_no);
        if (!authenticate_ev2_first(card, &ioReq, key, key_no, &sess0)) {
            printf("Provisioning: authentication failed.\n");
            goto cleanup;
        }

        uint8_t old_key[16] = {0};
        if (!change_key(card, &ioReq, &sess0, new_key_no, old_key, new_key, 0x01, &sw)) {
            printf("Provisioning: ChangeKey failed (SW1SW2=%04X)\n", sw);
            goto cleanup;
        }
        printf("Provisioning: ChangeKey OK (KeyNo 0x%02X)\n", new_key_no);
        new_key_set = 1;

        if (new_key_set) {
            memcpy(counter_key, new_key, sizeof(counter_key));
            counter_key_no = new_key_no;
        }
    }

    if (do_rotate_key) {
        if (rotate_key_no > 0x0F) {
            printf("Rotate: key number must be 0x00..0x0F\n");
            goto cleanup;
        }
        if (!rotate_old_key_path) {
            printf("Rotate: --old-key PATH is required\n");
            goto cleanup;
        }

        uint8_t old_key[16];
        if (!read_key_file(rotate_old_key_path, old_key)) {
            printf("Rotate: failed to read old key file: %s\n", rotate_old_key_path);
            goto cleanup;
        }

        uint8_t rotate_new_key[16];
        if (rotate_new_key_in_path) {
            if (!read_key_file(rotate_new_key_in_path, rotate_new_key)) {
                printf("Rotate: failed to read new key file: %s\n", rotate_new_key_in_path);
                goto cleanup;
            }
            printf("Rotate: using new key from %s (KeyNo 0x%02X)\n", rotate_new_key_in_path, rotate_key_no);
        } else {
            if (!rotate_new_key_path) {
                snprintf(key_out_buf, sizeof(key_out_buf), "ntag424_key%u_new.hex", rotate_key_no);
                rotate_new_key_path = key_out_buf;
            }
            random_bytes(rotate_new_key, sizeof(rotate_new_key));
            if (!write_key_hex_file(rotate_new_key_path, rotate_new_key)) {
                printf("Rotate: failed to write new key file: %s\n", rotate_new_key_path);
                goto cleanup;
            }
            printf("Rotate: new key (KeyNo 0x%02X) written to %s\n", rotate_key_no, rotate_new_key_path);
        }

        ssm_session_t sess0;
        memset(&sess0, 0, sizeof(sess0));
        printf("Rotate: authenticating with KeyNo 0x%02X for ChangeKey...\n", key_no);
        if (!authenticate_ev2_first(card, &ioReq, key, key_no, &sess0)) {
            printf("Rotate: authentication failed.\n");
            goto cleanup;
        }

        if (!change_key(card, &ioReq, &sess0, rotate_key_no, old_key, rotate_new_key, 0x01, &sw)) {
            printf("Rotate: ChangeKey failed (SW1SW2=%04X)\n", sw);
            goto cleanup;
        }
        printf("Rotate: ChangeKey OK (KeyNo 0x%02X)\n", rotate_key_no);

        if (rotate_key_no == counter_key_no) {
            memcpy(counter_key, rotate_new_key, sizeof(counter_key));
        }
    }

    if (do_sdm_setup) {
        if (sdm_key_no > 0x0F) {
            printf("SDM setup: SDM key number must be 0x00..0x0F\n");
            goto cleanup;
        }

        sdm_ndef_t sdm;
        if (!build_sdm_ndef(sdm_base_url, &sdm)) {
            printf("SDM setup: failed to build NDEF from base URL: %s\n", sdm_base_url);
            goto cleanup;
        }

        printf("SDM URL template: %s\n", sdm.url);
        printf("SDM offsets: UID=0x%06X CTR=0x%06X MACInput=0x%06X MAC=0x%06X\n",
               sdm.uid_offset, sdm.ctr_offset, sdm.mac_input_offset, sdm.mac_offset);

        ssm_session_t sess_cfg;
        memset(&sess_cfg, 0, sizeof(sess_cfg));
        printf("SDM setup: authenticating with KeyNo 0x%02X for ChangeFileSettings...\n", key_no);
        if (!authenticate_ev2_first(card, &ioReq, key, key_no, &sess_cfg)) {
            printf("SDM setup: authentication failed.\n");
            free(sdm.ndef);
            goto cleanup;
        }

        uint8_t ar1 = fs_info.valid ? fs_info.ar1 : 0xE0;
        uint8_t ar2 = fs_info.valid ? fs_info.ar2 : 0xEE;
        uint8_t sdm_options = 0xC1; // UID+ReadCtr mirroring, ASCII mode
        uint8_t sdm_meta = 0x0E;    // plain meta
        uint8_t sdm_file = sdm_key_no;
        uint8_t sdm_ctr = sdm_key_no;
        if (!change_file_settings_sdm(card, &ioReq, &sess_cfg, counter_file_no, 0x00,
                                      ar1, ar2, sdm_options,
                                      sdm_meta, sdm_file, sdm_ctr,
                                      sdm.uid_offset, sdm.ctr_offset,
                                      sdm.mac_input_offset, sdm.mac_offset,
                                      &sw)) {
            printf("SDM setup: ChangeFileSettings failed (SW1SW2=%04X)\n", sw);
            free(sdm.ndef);
            goto cleanup;
        }
        printf("SDM setup: ChangeFileSettings OK\n");

        if (!write_ndef_file_plain(card, &ioReq, sdm.ndef, sdm.ndef_len, &sw)) {
            printf("SDM setup: write NDEF failed (SW1SW2=%04X)\n", sw);
            free(sdm.ndef);
            goto cleanup;
        }
        printf("SDM setup: NDEF template written (%zu bytes)\n", sdm.ndef_len);
        free(sdm.ndef);

        fs_len = sizeof(fs_data);
        if (get_file_settings_plain(card, &ioReq, counter_file_no, fs_data, &fs_len, &sw)) {
            if (!parse_file_settings(fs_data, fs_len, &fs_info)) {
                printf("FileSettings: parse error\n");
            }
        } else {
            printf("FileSettings: GET failed (SW1SW2=%04X), trying secure...\n", sw);
            fs_len = sizeof(fs_data);
            if (get_file_settings_secure(card, &ioReq, &sess_cfg, counter_file_no, fs_data, &fs_len, &sw)) {
                if (!parse_file_settings(fs_data, fs_len, &fs_info)) {
                    printf("FileSettings: parse error\n");
                }
            } else {
                printf("FileSettings: secure GET failed (SW1SW2=%04X)\n", sw);
            }
        }
    }

    uint32_t counter = 0;
    if (get_sdm_read_counter(card, &ioReq, counter_file_no, &counter, &sw)) {
        printf("SDM Read Counter (plain, FileNo 0x%02X): %u\n", counter_file_no, counter);
    } else {
        printf("SDM Read Counter (plain): unavailable (SW1SW2=%04X)\n", sw);
    }

    ssm_session_t sess;
    memset(&sess, 0, sizeof(sess));
    printf("Authenticating (EV2First) with KeyNo 0x%02X...\n", counter_key_no);
    if (!authenticate_ev2_first(card, &ioReq, counter_key, counter_key_no, &sess)) {
        printf("Authentication failed.\n");
    } else {
        printf("Authentication OK. TI: ");
        print_hex(sess.ti, 4);
        printf("\n");

        if (fs_plain_failed) {
            printf("FileSettings: retrying with secure messaging...\n");
            fs_len = sizeof(fs_data);
            if (get_file_settings_secure(card, &ioReq, &sess, counter_file_no, fs_data, &fs_len, &sw)) {
                if (!parse_file_settings(fs_data, fs_len, &fs_info)) {
                    printf("FileSettings: parse error\n");
                }
            } else {
                printf("FileSettings: secure GET failed (SW1SW2=%04X)\n", sw);
            }
        }

        uint8_t header = counter_file_no;
        uint8_t resp[16];
        size_t resp_len = sizeof(resp);
        uint16_t sw2 = 0;
        if (ssm_cmd_full(card, &ioReq, &sess, 0xF6, &header, 1, NULL, 0, resp, &resp_len, &sw2)) {
            if (resp_len >= 3) {
                uint32_t c = (uint32_t)resp[0] | ((uint32_t)resp[1] << 8) | ((uint32_t)resp[2] << 16);
                printf("SDM Read Counter (secure, FileNo 0x%02X): %u\n", counter_file_no, c);
            } else {
                printf("SDM Read Counter (secure): response too short (%zu bytes)\n", resp_len);
            }
        } else {
            printf("SDM Read Counter (secure): failed (SW1SW2=%04X)\n", sw2);
        }
    }

cleanup:
    SCardDisconnect(card, SCARD_LEAVE_CARD);
    free(readers);
    SCardReleaseContext(ctx);
    return 0;
}
