#pragma once

#include "keel/array.h"
#include "keel/compress/deflate.h"
#include "keel/core.h"
#include "keel/ref.h"
#include "keel/result.h"

namespace keel::compress {

// ---------------------------------------------------------------------------
// LZ4 Raw Block Format (high-speed LZ77)
// ---------------------------------------------------------------------------
[[nodiscard]] inline usize lz4_compress_bound(usize input_size) noexcept {
    return input_size + (input_size / 255u) + 16u;
}

// Compresses a raw LZ4 block.
[[nodiscard]] Array<u8> lz4_compress_block(ArrayRef<u8> src, Allocator* alloc = nullptr);

// Decompresses a raw LZ4 block with an exact or maximum output size bound.
// Returns ErrorCode::OutOfRange if output exceeds max_output_bytes,
// ErrorCode::EndOfFile on truncation, or ErrorCode::InvalidData on malformed offset/match.
[[nodiscard]] Result<Array<u8>> lz4_decompress_block(ArrayRef<u8> src,
                                                     usize max_output_bytes = kDefaultMaxDecompressBytes,
                                                     Allocator* alloc = nullptr);

// ---------------------------------------------------------------------------
// LZ4 Frame Format (Official LZ4 Frame Format Specification v1.6.4)
// Supports ContentSize, BlockChecksum, ContentChecksum (XXH32),
// independent blocks (64KB / 256KB / 1MB / 4MB), and skippable frames.
// ---------------------------------------------------------------------------
enum class Lz4BlockSize : u8 {
    Max64KB = 4u,
    Max256KB = 5u,
    Max1MB = 6u,
    Max4MB = 7u,
};

struct Lz4FrameOptions {
    Lz4BlockSize block_size = Lz4BlockSize::Max4MB;
    bool content_checksum = true;
    bool block_checksum = false;
    bool write_content_size = true;
    Allocator* allocator = nullptr;
};

[[nodiscard]] Array<u8> lz4_frame_compress(ArrayRef<u8> src, const Lz4FrameOptions& opts = {});

[[nodiscard]] Result<Array<u8>> lz4_frame_decompress(ArrayRef<u8> src, const InflateOptions& opts = {});

} // namespace keel::compress
