#include "keel/compress/checksum.h"

#include "keel/memory.h"

namespace keel::compress {

namespace {

// ---------------------------------------------------------------------------
// Slicing-by-8 CRC-32 table generator (compile-time, 8 x 256 u32 = 8 KiB)
// ---------------------------------------------------------------------------
struct CrcSlice8Table {
    u32 t[8][256]{};
};

consteval CrcSlice8Table make_crc_slice8_table(u32 poly) noexcept {
    CrcSlice8Table tbl{};
    for (u32 i = 0u; i < 256u; ++i) {
        u32 c = i;
        for (u32 k = 0u; k < 8u; ++k) {
            c = (c & 1u) ? (poly ^ (c >> 1u)) : (c >> 1u);
        }
        tbl.t[0][i] = c;
    }
    for (u32 s = 1u; s < 8u; ++s) {
        for (u32 i = 0u; i < 256u; ++i) {
            const u32 prev = tbl.t[s - 1u][i];
            tbl.t[s][i] = tbl.t[0][prev & 0xFFu] ^ (prev >> 8u);
        }
    }
    return tbl;
}

constexpr u32 kCrc32Poly = 0xEDB88320u;
constexpr u32 kCrc32cPoly = 0x82F63B78u;

constexpr CrcSlice8Table kCrc32Table = make_crc_slice8_table(kCrc32Poly);
constexpr CrcSlice8Table kCrc32cTable = make_crc_slice8_table(kCrc32cPoly);

constexpr u32 load_le32(const u8* p) noexcept {
    return as<u32>(p[0]) | (as<u32>(p[1]) << 8u) | (as<u32>(p[2]) << 16u) | (as<u32>(p[3]) << 24u);
}

constexpr u64 load_le64(const u8* p) noexcept {
    return as<u64>(load_le32(p)) | (as<u64>(load_le32(p + 4u)) << 32u);
}

u32 crc_slice8_update(const CrcSlice8Table& tbl, u32 crc, ArrayRef<u8> data) noexcept {
    u32 c = crc ^ 0xFFFFFFFFu;
    const u8* ptr = data.data();
    usize len = data.size();

    while (len >= 8u) {
        const u32 lo = load_le32(ptr) ^ c;
        const u32 hi = load_le32(ptr + 4u);
        c = tbl.t[7][lo & 0xFFu] ^
            tbl.t[6][(lo >> 8u) & 0xFFu] ^
            tbl.t[5][(lo >> 16u) & 0xFFu] ^
            tbl.t[4][(lo >> 24u) & 0xFFu] ^
            tbl.t[3][hi & 0xFFu] ^
            tbl.t[2][(hi >> 8u) & 0xFFu] ^
            tbl.t[1][(hi >> 16u) & 0xFFu] ^
            tbl.t[0][(hi >> 24u) & 0xFFu];
        ptr += 8u;
        len -= 8u;
    }
    while (len > 0u) {
        c = tbl.t[0][(c ^ *ptr++) & 0xFFu] ^ (c >> 8u);
        --len;
    }
    return c ^ 0xFFFFFFFFu;
}

// GF(2) matrix helpers for crc32_combine / crc32c_combine
u32 gf2_matrix_times(const u32 mat[32], u32 vec) noexcept {
    u32 sum = 0u;
    usize idx = 0u;
    while (vec != 0u) {
        if ((vec & 1u) != 0u) sum ^= mat[idx];
        vec >>= 1u;
        ++idx;
    }
    return sum;
}

void gf2_matrix_square(u32 square[32], const u32 mat[32]) noexcept {
    for (usize n = 0u; n < 32u; ++n) {
        square[n] = gf2_matrix_times(mat, mat[n]);
    }
}

u32 crc_combine_impl(u32 poly, u32 crc1, u32 crc2, usize len2) noexcept {
    if (len2 == 0u) return crc1;

    u32 even[32];
    u32 odd[32];
    odd[0] = poly;
    u32 row = 1u;
    for (usize n = 1u; n < 32u; ++n) {
        odd[n] = row;
        row <<= 1u;
    }
    gf2_matrix_square(even, odd);
    gf2_matrix_square(odd, even);

    usize rem = len2;
    do {
        gf2_matrix_square(even, odd);
        if ((rem & 1u) != 0u) crc1 = gf2_matrix_times(even, crc1);
        rem >>= 1u;
        if (rem == 0u) break;

        gf2_matrix_square(odd, even);
        if ((rem & 1u) != 0u) crc1 = gf2_matrix_times(odd, crc1);
        rem >>= 1u;
    } while (rem != 0u);

    return crc1 ^ crc2;
}

// ---------------------------------------------------------------------------
// xxHash constants & rotation helpers
// ---------------------------------------------------------------------------
constexpr u32 kXxh32Prime1 = 0x9E3779B1u;
constexpr u32 kXxh32Prime2 = 0x85EBCA77u;
constexpr u32 kXxh32Prime3 = 0xC2B2AE3Du;
constexpr u32 kXxh32Prime4 = 0x27D4EB2Fu;
constexpr u32 kXxh32Prime5 = 0x165667B1u;

constexpr u64 kXxh64Prime1 = 0x9E3779B185EBCA87ull;
constexpr u64 kXxh64Prime2 = 0xC2B2AE3D27D4EB4Full;
constexpr u64 kXxh64Prime3 = 0x165667B19E3779F9ull;
constexpr u64 kXxh64Prime4 = 0x85EBCA77C2B2AE63ull;
constexpr u64 kXxh64Prime5 = 0x27D4EB2F165667C5ull;

constexpr u32 rotl32(u32 x, u32 r) noexcept { return (x << r) | (x >> (32u - r)); }
constexpr u64 rotl64(u64 x, u32 r) noexcept { return (x << r) | (x >> (64u - r)); }

constexpr u32 xxh32_round(u32 acc, u32 input) noexcept {
    acc += input * kXxh32Prime2;
    acc = rotl32(acc, 13u);
    acc *= kXxh32Prime1;
    return acc;
}

constexpr u64 xxh64_round(u64 acc, u64 input) noexcept {
    acc += input * kXxh64Prime2;
    acc = rotl64(acc, 31u);
    acc *= kXxh64Prime1;
    return acc;
}

constexpr u64 xxh64_merge_round(u64 acc, u64 val) noexcept {
    val = xxh64_round(0u, val);
    acc ^= val;
    acc = acc * kXxh64Prime1 + kXxh64Prime4;
    return acc;
}

} // namespace

// ---------------------------------------------------------------------------
// CRC-32 / CRC-32C / Adler-32
// ---------------------------------------------------------------------------
u32 crc32_update(u32 crc, ArrayRef<u8> data) noexcept {
    return crc_slice8_update(kCrc32Table, crc, data);
}

u32 crc32_combine(u32 crc1, u32 crc2, usize len2) noexcept {
    return crc_combine_impl(kCrc32Poly, crc1, crc2, len2);
}

u32 crc32c_update(u32 crc, ArrayRef<u8> data) noexcept {
    return crc_slice8_update(kCrc32cTable, crc, data);
}

u32 crc32c_combine(u32 crc1, u32 crc2, usize len2) noexcept {
    return crc_combine_impl(kCrc32cPoly, crc1, crc2, len2);
}

u32 adler32_update(u32 adler, ArrayRef<u8> data) noexcept {
    constexpr u32 kBase = 65521u;
    u32 s1 = adler & 0xFFFFu;
    u32 s2 = (adler >> 16u) & 0xFFFFu;

    const u8* ptr = data.data();
    usize len = data.size();
    while (len > 0u) {
        usize k = (len < 5552u) ? len : 5552u;
        len -= k;
        while (k >= 16u) {
            s1 += ptr[0];  s2 += s1;
            s1 += ptr[1];  s2 += s1;
            s1 += ptr[2];  s2 += s1;
            s1 += ptr[3];  s2 += s1;
            s1 += ptr[4];  s2 += s1;
            s1 += ptr[5];  s2 += s1;
            s1 += ptr[6];  s2 += s1;
            s1 += ptr[7];  s2 += s1;
            s1 += ptr[8];  s2 += s1;
            s1 += ptr[9];  s2 += s1;
            s1 += ptr[10]; s2 += s1;
            s1 += ptr[11]; s2 += s1;
            s1 += ptr[12]; s2 += s1;
            s1 += ptr[13]; s2 += s1;
            s1 += ptr[14]; s2 += s1;
            s1 += ptr[15]; s2 += s1;
            ptr += 16u;
            k -= 16u;
        }
        while (k > 0u) {
            s1 += *ptr++;
            s2 += s1;
            --k;
        }
        s1 %= kBase;
        s2 %= kBase;
    }
    return (s2 << 16u) | s1;
}

u32 adler32_combine(u32 adler1, u32 adler2, usize len2) noexcept {
    constexpr u64 kBase = 65521ull;
    const u64 rem = as<u64>(len2) % kBase;
    u64 sum1 = as<u64>(adler1 & 0xFFFFu);
    u64 sum2 = (rem * sum1) % kBase;
    sum1 += as<u64>(adler2 & 0xFFFFu) + kBase - 1ull;
    sum2 += as<u64>((adler1 >> 16u) & 0xFFFFu) + as<u64>((adler2 >> 16u) & 0xFFFFu) + kBase - rem;
    if (sum1 >= kBase) sum1 -= kBase;
    if (sum1 >= kBase) sum1 -= kBase;
    if (sum2 >= (kBase << 1u)) sum2 -= (kBase << 1u);
    if (sum2 >= kBase) sum2 -= kBase;
    return as<u32>(sum1 | (sum2 << 16u));
}

// ---------------------------------------------------------------------------
// xxHash32
// ---------------------------------------------------------------------------
void XxHash32::reset(u32 seed) noexcept {
    m_total_len = 0u;
    m_seed = seed;
    m_v1 = seed + kXxh32Prime1 + kXxh32Prime2;
    m_v2 = seed + kXxh32Prime2;
    m_v3 = seed;
    m_v4 = seed - kXxh32Prime1;
    m_buf_len = 0u;
}

void XxHash32::update(const u8* data, usize len) noexcept {
    if (len == 0u || !data) return;
    m_total_len += as<u64>(len);

    usize off = 0u;
    if (m_buf_len > 0u) {
        const usize want = 16u - as<usize>(m_buf_len);
        const usize take = (len < want) ? len : want;
        mem_copy(m_buf + m_buf_len, data, take);
        m_buf_len += as<u32>(take);
        off += take;
        if (m_buf_len == 16u) {
            m_v1 = xxh32_round(m_v1, load_le32(m_buf + 0u));
            m_v2 = xxh32_round(m_v2, load_le32(m_buf + 4u));
            m_v3 = xxh32_round(m_v3, load_le32(m_buf + 8u));
            m_v4 = xxh32_round(m_v4, load_le32(m_buf + 12u));
            m_buf_len = 0u;
        }
    }

    while (off + 16u <= len) {
        m_v1 = xxh32_round(m_v1, load_le32(data + off + 0u));
        m_v2 = xxh32_round(m_v2, load_le32(data + off + 4u));
        m_v3 = xxh32_round(m_v3, load_le32(data + off + 8u));
        m_v4 = xxh32_round(m_v4, load_le32(data + off + 12u));
        off += 16u;
    }

    if (off < len) {
        const usize rem = len - off;
        mem_copy(m_buf, data + off, rem);
        m_buf_len = as<u32>(rem);
    }
}

u32 XxHash32::finalize() const noexcept {
    u32 h32 = (m_total_len >= 16u)
        ? (rotl32(m_v1, 1u) + rotl32(m_v2, 7u) + rotl32(m_v3, 12u) + rotl32(m_v4, 18u))
        : (m_seed + kXxh32Prime5);

    h32 += as<u32>(m_total_len);

    usize off = 0u;
    const usize end = as<usize>(m_buf_len);
    while (off + 4u <= end) {
        h32 += load_le32(m_buf + off) * kXxh32Prime3;
        h32 = rotl32(h32, 17u) * kXxh32Prime4;
        off += 4u;
    }
    while (off < end) {
        h32 += as<u32>(m_buf[off]) * kXxh32Prime5;
        h32 = rotl32(h32, 11u) * kXxh32Prime1;
        ++off;
    }

    h32 ^= h32 >> 15u;
    h32 *= kXxh32Prime2;
    h32 ^= h32 >> 13u;
    h32 *= kXxh32Prime3;
    h32 ^= h32 >> 16u;
    return h32;
}

u32 XxHash32::hash(ArrayRef<u8> data, u32 seed) noexcept {
    XxHash32 h(seed);
    h.update(data);
    return h.finalize();
}

// ---------------------------------------------------------------------------
// xxHash64
// ---------------------------------------------------------------------------
void XxHash64::reset(u64 seed) noexcept {
    m_total_len = 0u;
    m_seed = seed;
    m_v1 = seed + kXxh64Prime1 + kXxh64Prime2;
    m_v2 = seed + kXxh64Prime2;
    m_v3 = seed;
    m_v4 = seed - kXxh64Prime1;
    m_buf_len = 0u;
}

void XxHash64::update(const u8* data, usize len) noexcept {
    if (len == 0u || !data) return;
    m_total_len += as<u64>(len);

    usize off = 0u;
    if (m_buf_len > 0u) {
        const usize want = 32u - as<usize>(m_buf_len);
        const usize take = (len < want) ? len : want;
        mem_copy(m_buf + m_buf_len, data, take);
        m_buf_len += as<u32>(take);
        off += take;
        if (m_buf_len == 32u) {
            m_v1 = xxh64_round(m_v1, load_le64(m_buf + 0u));
            m_v2 = xxh64_round(m_v2, load_le64(m_buf + 8u));
            m_v3 = xxh64_round(m_v3, load_le64(m_buf + 16u));
            m_v4 = xxh64_round(m_v4, load_le64(m_buf + 24u));
            m_buf_len = 0u;
        }
    }

    while (off + 32u <= len) {
        m_v1 = xxh64_round(m_v1, load_le64(data + off + 0u));
        m_v2 = xxh64_round(m_v2, load_le64(data + off + 8u));
        m_v3 = xxh64_round(m_v3, load_le64(data + off + 16u));
        m_v4 = xxh64_round(m_v4, load_le64(data + off + 24u));
        off += 32u;
    }

    if (off < len) {
        const usize rem = len - off;
        mem_copy(m_buf, data + off, rem);
        m_buf_len = as<u32>(rem);
    }
}

u64 XxHash64::finalize() const noexcept {
    u64 h64 = 0u;
    if (m_total_len >= 32u) {
        h64 = rotl64(m_v1, 1u) + rotl64(m_v2, 7u) + rotl64(m_v3, 12u) + rotl64(m_v4, 18u);
        h64 = xxh64_merge_round(h64, m_v1);
        h64 = xxh64_merge_round(h64, m_v2);
        h64 = xxh64_merge_round(h64, m_v3);
        h64 = xxh64_merge_round(h64, m_v4);
    } else {
        h64 = m_seed + kXxh64Prime5;
    }

    h64 += m_total_len;

    usize off = 0u;
    const usize end = as<usize>(m_buf_len);
    while (off + 8u <= end) {
        const u64 k1 = xxh64_round(0u, load_le64(m_buf + off));
        h64 ^= k1;
        h64 = rotl64(h64, 27u) * kXxh64Prime1 + kXxh64Prime4;
        off += 8u;
    }
    if (off + 4u <= end) {
        h64 ^= as<u64>(load_le32(m_buf + off)) * kXxh64Prime1;
        h64 = rotl64(h64, 23u) * kXxh64Prime2 + kXxh64Prime3;
        off += 4u;
    }
    while (off < end) {
        h64 ^= as<u64>(m_buf[off]) * kXxh64Prime5;
        h64 = rotl64(h64, 11u) * kXxh64Prime1;
        ++off;
    }

    h64 ^= h64 >> 33u;
    h64 *= kXxh64Prime2;
    h64 ^= h64 >> 29u;
    h64 *= kXxh64Prime3;
    h64 ^= h64 >> 32u;
    return h64;
}

u64 XxHash64::hash(ArrayRef<u8> data, u64 seed) noexcept {
    XxHash64 h(seed);
    h.update(data);
    return h.finalize();
}

} // namespace keel::compress
