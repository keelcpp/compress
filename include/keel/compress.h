#pragma once

#include "keel/array.h"
#include "keel/result.h"

namespace keel::compress {

inline constexpr usize kDefaultMaxDecompressBytes = 512ULL * 1024 * 1024;

struct InflateOptions {
    usize expected_size_hint = 0;
    usize max_output_bytes = kDefaultMaxDecompressBytes;
    Allocator* allocator = nullptr;
};

// IEEE 802.3 CRC-32 (polynomial 0xEDB88320). Initial state is 0.
[[nodiscard]] u32 crc32_update(u32 crc, ArrayRef<u8> data) noexcept;
[[nodiscard]] inline u32 crc32(ArrayRef<u8> data) noexcept { return crc32_update(0u, data); }

// RFC 1950 Adler-32. Initial state is 1.
[[nodiscard]] u32 adler32_update(u32 adler, ArrayRef<u8> data) noexcept;
[[nodiscard]] inline u32 adler32(ArrayRef<u8> data) noexcept { return adler32_update(1u, data); }

// RFC 1951 raw Deflate decompression.
// Possible error codes:
//   - ErrorCode::EndOfFile   : unexpected end of compressed bitstream
//   - ErrorCode::OutOfRange  : uncompressed output exceeds opts.max_output_bytes (when > 0)
//   - ErrorCode::InvalidData : malformed block header, Huffman table, or LZ77 back-reference
[[nodiscard]] Result<Array<u8>> inflate_raw(ArrayRef<u8> src, const InflateOptions& opts = {});

// RFC 1951 raw Deflate compression.
// level == 0 emits stored uncompressed blocks; level 1..9 uses LZ77 + Fixed Huffman.
[[nodiscard]] Array<u8> deflate_raw(ArrayRef<u8> src, i32 level = 6, Allocator* alloc = nullptr);

// RFC 1950 ZLIB stream decompression (2-byte header + Deflate payload + 4-byte Adler-32).
// Possible error codes:
//   - ErrorCode::EndOfFile    : truncated ZLIB wrapper or Deflate payload
//   - ErrorCode::NotSupported : unsupported compression method or preset dictionary (FDICT)
//   - ErrorCode::OutOfRange   : uncompressed output exceeds opts.max_output_bytes (when > 0)
//   - ErrorCode::InvalidData  : header checksum failure, corrupted Deflate data, or Adler-32 mismatch
[[nodiscard]] Result<Array<u8>> zlib_decompress(ArrayRef<u8> src, const InflateOptions& opts = {});

// RFC 1950 ZLIB stream compression (2-byte header + Deflate payload + 4-byte big-endian Adler-32).
[[nodiscard]] Array<u8> zlib_compress(ArrayRef<u8> src, i32 level = 6, Allocator* alloc = nullptr);

} // namespace keel::compress
