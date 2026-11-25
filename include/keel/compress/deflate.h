#pragma once

#include "keel/array.h"
#include "keel/core.h"
#include "keel/ref.h"
#include "keel/result.h"

namespace keel::compress {

inline constexpr usize kDefaultMaxDecompressBytes = 512ULL * 1024 * 1024;

struct InflateOptions {
    usize expected_size_hint = 0u;
    usize max_output_bytes = kDefaultMaxDecompressBytes;
    Allocator* allocator = nullptr;
};

// RFC 1951 raw Deflate decompression.
// Possible error codes:
//   - ErrorCode::EndOfFile   : unexpected end of compressed bitstream
//   - ErrorCode::OutOfRange  : uncompressed output exceeds opts.max_output_bytes (when > 0)
//   - ErrorCode::InvalidData : malformed block header, Huffman table, or LZ77 back-reference
[[nodiscard]] Result<Array<u8>> inflate_raw(ArrayRef<u8> src, const InflateOptions& opts = {});

// Same as inflate_raw, also reporting the exact number of compressed input bytes consumed.
[[nodiscard]] Result<Array<u8>> inflate_raw_ex(ArrayRef<u8> src, usize& consumed_out,
                                               const InflateOptions& opts = {});

// RFC 1951 raw Deflate compression.
// level == 0 emits stored blocks; level 1..9 uses LZ77 (with lazy matching on level >= 4)
// and automatically selects the smallest of Dynamic Huffman, Fixed Huffman, and Stored per block.
[[nodiscard]] Array<u8> deflate_raw(ArrayRef<u8> src, i32 level = 6, Allocator* alloc = nullptr);

// RFC 1950 ZLIB stream decompression (2-byte header + Deflate payload + 4-byte Adler-32).
[[nodiscard]] Result<Array<u8>> zlib_decompress(ArrayRef<u8> src, const InflateOptions& opts = {});

// RFC 1950 ZLIB stream compression (2-byte header + Deflate payload + 4-byte big-endian Adler-32).
[[nodiscard]] Array<u8> zlib_compress(ArrayRef<u8> src, i32 level = 6, Allocator* alloc = nullptr);

// ---------------------------------------------------------------------------
// Streaming Deflate / ZLIB / GZIP compressor
// Maintains a 32 KiB sliding window across blocks so arbitrarily large inputs
// can be compressed chunk-by-chunk with bounded memory.
// ---------------------------------------------------------------------------
enum class StreamFormat : u8 {
    Raw = 0u,
    Zlib = 1u,
    Gzip = 2u,
};

class DeflateStream {
public:
    explicit DeflateStream(StreamFormat fmt = StreamFormat::Zlib, i32 level = 6,
                           Allocator* alloc = nullptr);
    ~DeflateStream() noexcept = default;
    DeflateStream(const DeflateStream&) = delete;
    DeflateStream& operator=(const DeflateStream&) = delete;
    DeflateStream(DeflateStream&&) noexcept = default;
    DeflateStream& operator=(DeflateStream&&) noexcept = default;

    // Feeds an arbitrary chunk of uncompressed bytes. Emits compressed blocks as needed.
    void update(ArrayRef<u8> data);
    void update(const u8* data, usize len) { update(ArrayRef<u8>(data, len)); }

    // Drains all compressed bytes produced so far (may be called between update() calls).
    [[nodiscard]] Array<u8> take_output();

    // Finalizes the stream (BFINAL=1 + wrapper trailer) and returns all remaining output bytes.
    [[nodiscard]] Array<u8> finish();

    [[nodiscard]] bool is_finished() const noexcept { return m_finished; }

private:
    void flush_block(bool is_final);

    StreamFormat m_format = StreamFormat::Zlib;
    i32 m_level = 6;
    Allocator* m_alloc = nullptr;
    Array<u8> m_window;     // Up to 32 KiB history + 64 KiB pending block
    usize m_hist_len = 0u;  // Bytes in m_window that belong to prior block history
    Array<u8> m_out;
    u32 m_bit_buf = 0u;
    i32 m_bit_count = 0;
    u32 m_adler = 1u;
    u32 m_crc = 0u;
    u64 m_total_in = 0u;
    bool m_header_written = false;
    bool m_finished = false;
};

} // namespace keel::compress
