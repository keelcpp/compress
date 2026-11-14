#include "keel/compress.h"

#include "keel/arena.h"

#include <cstdio>
#include <cstring>

using namespace keel;

namespace {

int g_tests_passed = 0;
int g_tests_failed = 0;

#define TEST_CHECK(cond)                                                                                               \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            std::fprintf(stderr, "FAIL: %s (%s:%d)\n", #cond, __FILE__, __LINE__);                                     \
            ++g_tests_failed;                                                                                          \
        } else {                                                                                                       \
            ++g_tests_passed;                                                                                          \
        }                                                                                                              \
    } while (0)

void test_checksums() {
    const u8 empty_dummy = 0;
    ArrayRef<u8> empty(&empty_dummy, 0);
    TEST_CHECK(crc32(empty) == 0x00000000u);
    TEST_CHECK(adler32(empty) == 0x00000001u);

    const char* text = "123456789";
    ArrayRef<u8> vec(reinterpret_cast<const u8*>(text), 9);
    TEST_CHECK(crc32(vec) == 0xCBF43926u);
    TEST_CHECK(adler32(vec) == 0x091E01DEu);

    // Incremental update equivalence
    const u32 c_part = crc32_update(0u, vec.slice(0, 4));
    const u32 c_full = crc32_update(c_part, vec.slice(4));
    TEST_CHECK(c_full == 0xCBF43926u);

    const u32 a_part = adler32_update(1u, vec.slice(0, 4));
    const u32 a_full = adler32_update(a_part, vec.slice(4));
    TEST_CHECK(a_full == 0x091E01DEu);

    // Large buffer (> 5552 NMAX blocks for Adler-32)
    Array<u8> large(16000, 0xABu);
    const u32 a1 = adler32(large);
    const u32 a2 = adler32_update(adler32_update(1u, large.slice(0, 7777)), large.slice(7777));
    TEST_CHECK(a1 == a2);
}

void test_empty_and_small_roundtrip() {
    ArrayRef<u8> empty{};
    for (int lvl : {0, 1, 6, 9}) {
        Array<u8> raw_comp = deflate_raw(empty, lvl);
        auto raw_dec = inflate_raw(raw_comp);
        TEST_CHECK(raw_dec.is_ok());
        if (raw_dec) TEST_CHECK(raw_dec->empty());

        Array<u8> z_comp = zlib_compress(empty, lvl);
        auto z_dec = zlib_decompress(z_comp);
        TEST_CHECK(z_dec.is_ok());
        if (z_dec) TEST_CHECK(z_dec->empty());
    }

    const char* msg = "Hello from keel::compress! Testing LZ77 + Fixed Huffman & RFC 1950 ZLIB.";
    ArrayRef<u8> msg_bytes(reinterpret_cast<const u8*>(msg), std::strlen(msg));
    for (int lvl : {0, 1, 6, 9}) {
        Array<u8> raw_comp = deflate_raw(msg_bytes, lvl);
        auto raw_dec = inflate_raw(raw_comp);
        TEST_CHECK(raw_dec.is_ok() && *raw_dec == msg_bytes);

        Array<u8> z_comp = zlib_compress(msg_bytes, lvl);
        auto z_dec = zlib_decompress(z_comp);
        TEST_CHECK(z_dec.is_ok() && *z_dec == msg_bytes);
    }
}

void test_multi_block_and_repetitive() {
    // Repetitive 150 KB (> 2x 65535 stored block size, exercises multi-block stored & RLE distance=1)
    Array<u8> rep(150000, 0x42u);
    Array<u8> z_stored = zlib_compress(rep, 0);
    auto dec_stored = zlib_decompress(z_stored);
    TEST_CHECK(dec_stored.is_ok() && *dec_stored == rep);

    Array<u8> z_fast = zlib_compress(rep, 6);
    TEST_CHECK(z_fast.size() < 1200u);
    auto dec_fast = zlib_decompress(z_fast);
    TEST_CHECK(dec_fast.is_ok() && *dec_fast == rep);

    // Pseudo-random + patterned 80 KB payload (exercises hash chains and cross-window distances)
    Array<u8> mixed(80000);
    u32 rng = 0x12345678u;
    for (usize i = 0; i < mixed.size(); ++i) {
        rng = rng * 1664525u + 1013904223u;
        mixed[i] = static_cast<u8>((i % 251u) ^ ((rng >> 24) & 0x1Fu));
    }
    for (int lvl : {0, 1, 6, 9}) {
        Array<u8> zc = zlib_compress(mixed, lvl);
        auto zd = zlib_decompress(zc, InflateOptions{.expected_size_hint = mixed.size()});
        TEST_CHECK(zd.is_ok() && *zd == mixed);
    }
}

void test_dynamic_huffman_vector() {
    // True BTYPE=2 (Dynamic Huffman) ZLIB stream produced by standard zlib (level 9)
    // for 256 LCG-generated symbols in {'A', 'B', 'C', 'D'}.
    const u8 dyn_vec[] = {
        0x78, 0xDA, 0x25, 0x8F, 0x89, 0x0D, 0x80, 0x30, 0x0C, 0x03, 0x67, 0xF3, 0xB3, 0xFF, 0x4C, 0xF5, 0xA5,
        0x2A, 0xA8, 0x26, 0xF1, 0x47, 0xE2, 0xB6, 0xA9, 0x76, 0x4B, 0xEE, 0x4E, 0x92, 0x1B, 0x39, 0x1B, 0x80,
        0x63, 0x8B, 0xDD, 0x40, 0x93, 0xE1, 0x42, 0xF1, 0x09, 0xA7, 0x34, 0x8A, 0x68, 0xCF, 0x50, 0x6F, 0x5F,
        0x6B, 0xC7, 0x9A, 0xC7, 0xF6, 0x0C, 0xEF, 0xBD, 0x8F, 0xD9, 0x8E, 0x39, 0x3A, 0x6C, 0xBC, 0x43, 0xCE,
        0x44, 0xA4, 0x1F, 0xBF, 0x38, 0x1B, 0x03, 0x32, 0x90, 0x41, 0x09, 0x4D, 0xCF, 0x3C, 0x57, 0x66, 0xEE,
        0x21, 0x87, 0xC6, 0x60, 0x7E, 0xE0, 0x97, 0x81, 0x30, 0x6B, 0x11, 0xB5, 0x11, 0xD4, 0x9B, 0xCD, 0x7C,
        0x3A, 0x61, 0x21, 0xBA, 0x10, 0xF7, 0x00, 0x73, 0xE3, 0x42, 0x96,
    };
    TEST_CHECK(((dyn_vec[2] >> 1) & 3u) == 2u); // Confirm BTYPE=10 (Dynamic Huffman)

    Array<u8> expected(256);
    u32 rng = 1u;
    for (usize i = 0; i < 256; ++i) {
        rng = (rng * 1103515245u + 12345u) & 0x7FFFFFFFu;
        expected[i] = static_cast<u8>(65u + ((rng >> 16) & 3u));
    }

    auto dec = zlib_decompress(dyn_vec);
    TEST_CHECK(dec.is_ok() && *dec == expected);
}

void test_safety_and_errors() {
    // 1. Decompression bomb cap (OutOfRange)
    Array<u8> zeros(64 * 1024, u8{0});
    Array<u8> bomb = zlib_compress(zeros, 6);
    auto capped = zlib_decompress(bomb, InflateOptions{.max_output_bytes = 1024});
    TEST_CHECK(capped.is_err() && capped.error().code == ErrorCode::OutOfRange);

    // 2. Truncated ZLIB stream
    TEST_CHECK(zlib_decompress(bomb.slice(0, 3)).error().code == ErrorCode::EndOfFile);
    TEST_CHECK(zlib_decompress(bomb.slice(0, bomb.size() - 5)).error().code == ErrorCode::EndOfFile);

    // 3. Bad ZLIB header checksum
    Array<u8> bad_hdr = bomb.clone();
    bad_hdr[0] ^= 0x01u;
    TEST_CHECK(zlib_decompress(bad_hdr).error().code == ErrorCode::InvalidData);

    // 4. FDICT flag unsupported
    Array<u8> fdict_hdr = bomb.clone();
    fdict_hdr[0] = 0x78u;
    fdict_hdr[1] = 0x20u;
    const u32 rem = ((0x78u << 8) + 0x20u) % 31u;
    if (rem != 0) fdict_hdr[1] = static_cast<u8>(0x20u + (31u - rem));
    TEST_CHECK(zlib_decompress(fdict_hdr).error().code == ErrorCode::NotSupported);

    // 5. Corrupted Adler-32 trailer
    Array<u8> bad_adler = bomb.clone();
    bad_adler[bad_adler.size() - 1] ^= 0xFFu;
    TEST_CHECK(zlib_decompress(bad_adler).error().code == ErrorCode::InvalidData);

    // 6. Reserved Deflate block type 3 (bfinal=1, btype=11 -> 0x07)
    const u8 bad_btype[] = {0x07u};
    TEST_CHECK(inflate_raw(bad_btype).error().code == ErrorCode::InvalidData);

    // 7. Custom Arena allocator routing
    Arena custom_arena(1024 * 1024);
    const usize before = custom_arena.used();
    Array<u8> arena_comp = zlib_compress(zeros.slice(0, 512), 6, custom_arena.allocator());
    TEST_CHECK(custom_arena.used() > before);
    auto arena_dec = zlib_decompress(arena_comp, InflateOptions{.allocator = custom_arena.allocator()});
    TEST_CHECK(arena_dec.is_ok() && arena_dec->size() == 512);
    TEST_CHECK(arena_dec->allocator() == custom_arena.allocator());
}

} // namespace

int main() {
    test_checksums();
    test_empty_and_small_roundtrip();
    test_multi_block_and_repetitive();
    test_dynamic_huffman_vector();
    test_safety_and_errors();

    if (g_tests_failed != 0) {
        std::fprintf(stderr, "%d test check(s) FAILED (%d passed)\n", g_tests_failed, g_tests_passed);
        return 1;
    }
    std::printf("All %d keel::compress test checks passed.\n", g_tests_passed);
    return 0;
}
