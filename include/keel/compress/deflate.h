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

// ---------------------------------------------------------------------------
// Streaming Deflate / ZLIB / GZIP decompressor (bounded 32 KiB sliding window)
// Accepts arbitrarily small chunks (down to 1 byte at a time).
// Supports concatenated multi-member GZIP streams, Adler-32 / CRC-32 / ISIZE /
// FHCRC verification, and decompression-bomb caps via opts.max_output_bytes.
// ---------------------------------------------------------------------------
class InflateStream {
public:
    explicit InflateStream(StreamFormat fmt = StreamFormat::Zlib, const InflateOptions& opts = {});
    ~InflateStream() noexcept = default;
    InflateStream(const InflateStream&) = delete;
    InflateStream& operator=(const InflateStream&) = delete;
    InflateStream(InflateStream&&) noexcept = default;
    InflateStream& operator=(InflateStream&&) noexcept = default;

    // Feeds an arbitrary chunk of compressed bytes, appending decompressed bytes to `out`.
    [[nodiscard]] ErrorCode push(ArrayRef<u8> chunk, Array<u8>& out);
    [[nodiscard]] ErrorCode push(const u8* data, usize len, Array<u8>& out) {
        return push(ArrayRef<u8>(data, len), out);
    }

    // Validates clean stream termination (final block + wrapper trailer) after the last chunk.
    [[nodiscard]] ErrorCode finish() noexcept;

    [[nodiscard]] bool is_finished() const noexcept { return m_finished && m_error == ErrorCode::Ok; }
    [[nodiscard]] usize total_out() const noexcept { return m_total_out; }

private:
    struct StreamHuff {
        static constexpr i32 kPrimaryBits = 9;
        static constexpr usize kPrimarySize = usize{1u} << 9u;
        static constexpr u32 kInvalid = 0xFFu;

        u32 primary[kPrimarySize] = {};
        Array<u32> sub;
        bool empty = true;

        explicit StreamHuff(Allocator* alloc) : sub(alloc) {}
        [[nodiscard]] ErrorCode build(const u8* lens, i32 count, bool allow_empty = false);
    };

    enum class State : u8 {
        ZlibHdr,
        GzipHdrFixed,
        GzipExtraLen,
        GzipExtraSkip,
        GzipNameSkip,
        GzipCommentSkip,
        GzipHcrc,
        BlockHdr,
        StoredHdr,
        StoredBody,
        DynHdr,
        DynClLens,
        DynCodeLens,
        DecodeLitLen,
        DecodeLenExtra,
        DecodeDist,
        DecodeDistExtra,
        ZlibTrailer,
        GzipTrailer,
        GzipNextMember,
        Done,
        Failed,
    };

    [[nodiscard]] ErrorCode emit_byte(u8 b, Array<u8>& out);
    [[nodiscard]] ErrorCode emit_match(usize length, usize dist, Array<u8>& out);
    void reset_for_next_gzip_member() noexcept;

    StreamFormat m_format = StreamFormat::Zlib;
    usize m_max_out = kDefaultMaxDecompressBytes;
    Allocator* m_alloc = nullptr;
    State m_state = State::BlockHdr;
    ErrorCode m_error = ErrorCode::Ok;

    // Bit buffer
    u64 m_bit_buf = 0u;
    i32 m_bit_count = 0;

    // 32 KiB sliding window
    Array<u8> m_window;
    usize m_win_pos = 0u;
    usize m_win_fill = 0u;

    // Block / Huffman state
    bool m_bfinal = false;
    bool m_finished = false;
    StreamHuff m_lit_tree;
    StreamHuff m_dist_tree;
    StreamHuff m_cl_tree;
    u8 m_tmp[16] = {};
    usize m_tmp_pos = 0u;
    usize m_tmp_need = 0u;
    u8 m_gz_flg = 0u;
    u32 m_gz_hcrc = 0u;
    usize m_stored_rem = 0u;
    i32 m_hlit = 0;
    i32 m_hdist = 0;
    i32 m_hclen = 0;
    i32 m_cl_idx = 0;
    u8 m_cl_lens[19] = {};
    u8 m_all_lens[320] = {};
    i32 m_lens_idx = 0;
    i32 m_pending_cl_sym = -1;
    i32 m_pending_len_idx = 0;
    usize m_pending_length = 0u;
    i32 m_pending_dist_sym = 0;

    // Checksums & totals
    u32 m_adler = 1u;
    u32 m_crc = 0u;
    usize m_member_out = 0u;
    usize m_total_out = 0u;
};

} // namespace keel::compress
