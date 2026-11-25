# keelcpp/compress (`keel::compress`)

Zero-dependency C++20 compression, checksum, and archive library built on [`keelcpp/keel`](https://github.com/keelcpp/keel) (`0BSD`, Windows / Linux / WASM, `-fno-exceptions -fno-rtti`, verified under MSVC AddressSanitizer, Clang 19, and cross-checked against Python `zlib`, `gzip`, `zipfile`, and the LZ4 Frame v1.6.4 specification).

## Modules

- `keel/compress/checksum.h` — slicing-by-8 IEEE 802.3 **CRC-32** & Castagnoli **CRC-32C** (with `combine`), RFC 1950 **Adler-32** (with `combine`), and official streaming/one-shot **xxHash32** & **xxHash64**.
- `keel/compress/deflate.h` — RFC 1951 **Deflate** (LZ77 with lazy matching + length-limited **Dynamic Huffman**, **Fixed Huffman**, and automatic **Stored** fallback per block) & fast 2-level LUT **Inflate** with decompression-bomb caps (`max_output_bytes`), RFC 1950 **ZLIB**, and bounded-memory streaming **`DeflateStream`** (Raw / ZLIB / GZIP).
- `keel/compress/gzip.h` — RFC 1952 **GZIP** (`gzip_compress`, `gzip_decompress`, `gzip_peek_header`) with `FEXTRA` / `FNAME` / `FCOMMENT` / `FHCRC` and concatenated multi-member stream support.
- `keel/compress/lz4.h` — high-speed **LZ4 Raw Block** and official **LZ4 Frame Format v1.6.4** (`ContentSize`, `BlockChecksum`, `ContentChecksum` via XXH32, skippable frames, 64KB–4MB block sizes).
- `keel/compress/zip.h` — in-memory **ZIP** archive `ZipReader` and `ZipWriter` (Store & Deflate, UTF-8 entry names, CRC-32 validation, archive comments, and `is_safe_zip_path` Zip Slip protection).
- `keel/compress.h` — umbrella header.

## Building & Reference Verification

```bash
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure

# Differential verification against Python zlib, gzip, zipfile, and LZ4 Frame spec:
python tests/verify_reference.py build/Release/test_compress.exe
```

## CMake Integration

Links as `keel::compress` (`find_package(keel_compress)` or `FetchContent`).
