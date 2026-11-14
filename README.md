# keelcpp/compress

Lightweight C++20 compression & checksum primitives built on [`keelcpp/keel`](https://github.com/keelcpp/keel) under the `0BSD` license.

## Features

- **Checksums:** IEEE 802.3 `crc32` / `crc32_update` and RFC 1950 `adler32` / `adler32_update`.
- **RFC 1951 Deflate / Inflate:** `deflate_raw` (stored blocks + LZ77 Fixed Huffman) and `inflate_raw` (stored, Fixed Huffman, and Dynamic Huffman blocks) with configurable `max_output_bytes` protection against decompression bombs.
- **RFC 1950 ZLIB:** `zlib_compress` and `zlib_decompress` with header & Adler-32 validation.
- **Zero STL header bloat & exception-neutral:** compiles cleanly with `-fno-exceptions -fno-rtti`, uses explicit `keel::Allocator*` and thread-local `keel::Arena` scratch memory.

## CMake Integration

Links as `keel::compress` (`find_package(keel_compress)` or `FetchContent`).
