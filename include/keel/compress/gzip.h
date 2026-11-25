#pragma once

#include "keel/array.h"
#include "keel/compress/deflate.h"
#include "keel/core.h"
#include "keel/ref.h"
#include "keel/result.h"
#include "keel/string.h"

namespace keel::compress {

struct GzipOptions {
    i32 level = 6;
    u32 mtime = 0u;
    u8 os = 0xFFu;
    StringRef filename{};
    StringRef comment{};
    ArrayRef<u8> extra{};
    bool write_header_crc = false;
    Allocator* allocator = nullptr;
};

struct GzipHeader {
    u32 mtime = 0u;
    u8 xfl = 0u;
    u8 os = 0xFFu;
    bool is_text = false;
    String filename;
    String comment;
    Array<u8> extra;
    usize header_bytes = 0u;
};

// Parses the RFC 1952 GZIP header of the first member (validating magic, CM, reserved flags, and optional FHCRC).
[[nodiscard]] Result<GzipHeader> gzip_peek_header(ArrayRef<u8> src, Allocator* alloc = nullptr);

// RFC 1952 GZIP compression.
[[nodiscard]] Array<u8> gzip_compress(ArrayRef<u8> src, const GzipOptions& opts = {});
[[nodiscard]] inline Array<u8> gzip_compress(ArrayRef<u8> src, i32 level, Allocator* alloc = nullptr) {
    GzipOptions opts{};
    opts.level = level;
    opts.allocator = alloc;
    return gzip_compress(src, opts);
}

// RFC 1952 GZIP decompression.
// Supports concatenated multi-member GZIP streams, optional FEXTRA/FNAME/FCOMMENT/FHCRC,
// CRC-32 and ISIZE verification, and decompression bomb protection via opts.max_output_bytes.
[[nodiscard]] Result<Array<u8>> gzip_decompress(ArrayRef<u8> src, const InflateOptions& opts = {});

} // namespace keel::compress
