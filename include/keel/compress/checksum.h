#pragma once

#include "keel/core.h"
#include "keel/ref.h"

namespace keel::compress {

// ---------------------------------------------------------------------------
// IEEE 802.3 CRC-32 (polynomial 0xEDB88320, slicing-by-8). Initial state is 0.
// ---------------------------------------------------------------------------
[[nodiscard]] u32 crc32_update(u32 crc, ArrayRef<u8> data) noexcept;
[[nodiscard]] inline u32 crc32(ArrayRef<u8> data) noexcept { return crc32_update(0u, data); }
[[nodiscard]] u32 crc32_combine(u32 crc1, u32 crc2, usize len2) noexcept;

// ---------------------------------------------------------------------------
// Castagnoli CRC-32C (polynomial 0x82F63B78, slicing-by-8). Initial state is 0.
// ---------------------------------------------------------------------------
[[nodiscard]] u32 crc32c_update(u32 crc, ArrayRef<u8> data) noexcept;
[[nodiscard]] inline u32 crc32c(ArrayRef<u8> data) noexcept { return crc32c_update(0u, data); }
[[nodiscard]] u32 crc32c_combine(u32 crc1, u32 crc2, usize len2) noexcept;

// ---------------------------------------------------------------------------
// RFC 1950 Adler-32. Initial state is 1.
// ---------------------------------------------------------------------------
[[nodiscard]] u32 adler32_update(u32 adler, ArrayRef<u8> data) noexcept;
[[nodiscard]] inline u32 adler32(ArrayRef<u8> data) noexcept { return adler32_update(1u, data); }
[[nodiscard]] u32 adler32_combine(u32 adler1, u32 adler2, usize len2) noexcept;

// ---------------------------------------------------------------------------
// xxHash32 (XXH32 — used by LZ4 Frame checksums and fast hashing)
// ---------------------------------------------------------------------------
class XxHash32 {
public:
    explicit XxHash32(u32 seed = 0u) noexcept { reset(seed); }

    void reset(u32 seed = 0u) noexcept;
    void update(const u8* data, usize len) noexcept;
    void update(ArrayRef<u8> data) noexcept { update(data.data(), data.size()); }
    [[nodiscard]] u32 finalize() const noexcept;

    [[nodiscard]] static u32 hash(ArrayRef<u8> data, u32 seed = 0u) noexcept;

private:
    u64 m_total_len = 0u;
    u32 m_v1 = 0u;
    u32 m_v2 = 0u;
    u32 m_v3 = 0u;
    u32 m_v4 = 0u;
    u8 m_buf[16] = {};
    u32 m_buf_len = 0u;
    u32 m_seed = 0u;
};

[[nodiscard]] inline u32 xxhash32(ArrayRef<u8> data, u32 seed = 0u) noexcept {
    return XxHash32::hash(data, seed);
}

// ---------------------------------------------------------------------------
// xxHash64 (XXH64 — 64-bit high-throughput non-cryptographic hash)
// ---------------------------------------------------------------------------
class XxHash64 {
public:
    explicit XxHash64(u64 seed = 0u) noexcept { reset(seed); }

    void reset(u64 seed = 0u) noexcept;
    void update(const u8* data, usize len) noexcept;
    void update(ArrayRef<u8> data) noexcept { update(data.data(), data.size()); }
    [[nodiscard]] u64 finalize() const noexcept;

    [[nodiscard]] static u64 hash(ArrayRef<u8> data, u64 seed = 0u) noexcept;

private:
    u64 m_total_len = 0u;
    u64 m_v1 = 0u;
    u64 m_v2 = 0u;
    u64 m_v3 = 0u;
    u64 m_v4 = 0u;
    u8 m_buf[32] = {};
    u32 m_buf_len = 0u;
    u64 m_seed = 0u;
};

[[nodiscard]] inline u64 xxhash64(ArrayRef<u8> data, u64 seed = 0u) noexcept {
    return XxHash64::hash(data, seed);
}

} // namespace keel::compress
