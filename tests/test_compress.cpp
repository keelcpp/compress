#include "keel/compress.h"

#include "keel/arena.h"
#include "keel/format.h"
#include "keel/fs.h"
#include "keel/number.h"
#include "keel/string.h"

using namespace keel;
using namespace keel::compress;

namespace {

i32 g_tests_passed = 0;
i32 g_tests_failed = 0;

#define TEST_CHECK(cond)                                                                                               \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            keel::eprintln("FAIL: {} ({}:{})", #cond, __FILE__, __LINE__);                                             \
            ++g_tests_failed;                                                                                          \
        } else {                                                                                                       \
            ++g_tests_passed;                                                                                          \
        }                                                                                                              \
    } while (0)

void test_checksums() {
    const u8 empty_dummy = 0u;
    ArrayRef<u8> empty(&empty_dummy, 0u);
    TEST_CHECK(crc32(empty) == 0x00000000u);
    TEST_CHECK(crc32c(empty) == 0x00000000u);
    TEST_CHECK(adler32(empty) == 0x00000001u);

    const char* text = "123456789";
    ArrayRef<u8> vec(reinterpret_cast<const u8*>(text), 9u);
    TEST_CHECK(crc32(vec) == 0xCBF43926u);
    TEST_CHECK(crc32c(vec) == 0xE3069283u);
    TEST_CHECK(adler32(vec) == 0x091E01DEu);

    // Incremental update & combine equivalence across slicing-by-8 boundaries
    Array<u8> buf(16384u);
    u32 rng = 0xCAFEBABEu;
    for (usize i = 0u; i < buf.size(); ++i) {
        rng = rng * 1664525u + 1013904223u;
        buf[i] = as<u8>(rng >> 24u);
    }

    const usize split = 7777u;
    const ArrayRef<u8> part1 = buf.slice(0u, split);
    const ArrayRef<u8> part2 = buf.slice(split);

    TEST_CHECK(crc32_update(crc32(part1), part2) == crc32(buf));
    TEST_CHECK(crc32_combine(crc32(part1), crc32(part2), part2.size()) == crc32(buf));
    TEST_CHECK(crc32c_update(crc32c(part1), part2) == crc32c(buf));
    TEST_CHECK(crc32c_combine(crc32c(part1), crc32c(part2), part2.size()) == crc32c(buf));
    TEST_CHECK(adler32_update(adler32(part1), part2) == adler32(buf));
    TEST_CHECK(adler32_combine(adler32(part1), adler32(part2), part2.size()) == adler32(buf));

    // Official xxHash32 & xxHash64 test vectors (Cyan4973/xxHash xsum_sanity_check.c)
    constexpr u32 kPrime32 = 2654435761u;
    constexpr u64 kPrime64 = 11400714785074694797ull;
    Array<u8> xxh_buf(222u);
    u64 byte_gen = kPrime32;
    for (usize i = 0u; i < xxh_buf.size(); ++i) {
        xxh_buf[i] = as<u8>(byte_gen >> 56u);
        byte_gen *= kPrime64;
    }
    TEST_CHECK(xxhash32(empty, 0u) == 0x02CC5D05u);
    TEST_CHECK(xxhash32(empty, kPrime32) == 0x36B78AE7u);
    TEST_CHECK(xxhash32(xxh_buf.slice(0u, 1u), 0u) == 0xCF65B03Eu);
    TEST_CHECK(xxhash32(xxh_buf.slice(0u, 1u), kPrime32) == 0xB4545AA4u);
    TEST_CHECK(xxhash32(xxh_buf.slice(0u, 14u), 0u) == 0x1208E7E2u);
    TEST_CHECK(xxhash32(xxh_buf.slice(0u, 14u), kPrime32) == 0x6AF1D1FEu);
    TEST_CHECK(xxhash32(xxh_buf.slice(0u, 222u), 0u) == 0x5BD11DBDu);
    TEST_CHECK(xxhash32(xxh_buf.slice(0u, 222u), kPrime32) == 0x58803C5Fu);

    TEST_CHECK(xxhash64(empty, 0u) == 0xEF46DB3751D8E999ull);
    TEST_CHECK(xxhash64(empty, kPrime32) == 0xAC75FDA2929B17EFull);
    TEST_CHECK(xxhash64(xxh_buf.slice(0u, 1u), 0u) == 0xE934A84ADB052768ull);
    TEST_CHECK(xxhash64(xxh_buf.slice(0u, 1u), kPrime32) == 0x5014607643A9B4C3ull);
    TEST_CHECK(xxhash64(xxh_buf.slice(0u, 4u), 0u) == 0x9136A0DCA57457EEull);
    TEST_CHECK(xxhash64(xxh_buf.slice(0u, 14u), 0u) == 0x8282DCC4994E35C8ull);
    TEST_CHECK(xxhash64(xxh_buf.slice(0u, 14u), kPrime32) == 0xC3BD6BF63DEB6DF0ull);
    TEST_CHECK(xxhash64(xxh_buf.slice(0u, 222u), 0u) == 0xB641AE8CB691C174ull);
    TEST_CHECK(xxhash64(xxh_buf.slice(0u, 222u), kPrime32) == 0x20CB8AB7AE10C14Aull);

    // Streaming xxHash32/64 chunk-by-chunk equivalence
    XxHash32 x32(0x12345678u);
    XxHash64 x64(0x123456789ABCDEF0ull);
    for (usize i = 0u; i < buf.size(); i += 13u) {
        const usize n = keel::min<usize>(buf.size() - i, 13u);
        x32.update(buf.data() + i, n);
        x64.update(buf.data() + i, n);
    }
    TEST_CHECK(x32.finalize() == xxhash32(buf, 0x12345678u));
    TEST_CHECK(x64.finalize() == xxhash64(buf, 0x123456789ABCDEF0ull));
}

void test_deflate_zlib_and_streaming() {
    ArrayRef<u8> empty{};
    for (i32 lvl : {0, 1, 3, 6, 9}) {
        Array<u8> raw_comp = deflate_raw(empty, lvl);
        auto raw_dec = inflate_raw(raw_comp);
        TEST_CHECK(raw_dec.is_ok() && raw_dec->empty());

        Array<u8> z_comp = zlib_compress(empty, lvl);
        auto z_dec = zlib_decompress(z_comp);
        TEST_CHECK(z_dec.is_ok() && z_dec->empty());
    }

    // Skewed-alphabet payload that strongly benefits from Dynamic Huffman (BTYPE=2)
    Array<u8> skewed(32000u);
    u32 rng = 0x13579BDFu;
    for (usize i = 0u; i < skewed.size(); ++i) {
        rng = rng * 1664525u + 1013904223u;
        const u32 r = (rng >> 24u) & 15u;
        skewed[i] = (r < 9u) ? as<u8>('A') : ((r < 13u) ? as<u8>('B') : ((r < 15u) ? as<u8>('C') : as<u8>('D')));
    }
    Array<u8> dyn_raw = deflate_raw(skewed, 6);
    TEST_CHECK(((dyn_raw[0] >> 1u) & 3u) == 2u); // Dynamic Huffman chosen
    TEST_CHECK(dyn_raw.size() < skewed.size() / 3u);
    auto dyn_dec = inflate_raw(dyn_raw);
    TEST_CHECK(dyn_dec.is_ok() && *dyn_dec == skewed);

    // Incompressible random payload must automatically fall back to Stored (BTYPE=0, minimal overhead)
    Array<u8> random_incomp(10000u);
    for (usize i = 0u; i < random_incomp.size(); ++i) {
        rng = rng * 1664525u + 1013904223u;
        random_incomp[i] = as<u8>(rng >> 24u);
    }
    Array<u8> incomp_raw = deflate_raw(random_incomp, 6);
    TEST_CHECK(incomp_raw.size() <= random_incomp.size() + 16u);
    auto incomp_dec = inflate_raw(incomp_raw);
    TEST_CHECK(incomp_dec.is_ok() && *incomp_dec == random_incomp);

    // Multi-block repetitive + patterned 150 KB payload across levels 0..9
    Array<u8> big(150000u);
    for (usize i = 0u; i < big.size(); ++i) {
        big[i] = as<u8>((i < 50000u) ? 0x42u : ((i % 97u) ^ ((i / 1024u) & 0xFFu)));
    }
    for (i32 lvl : {0, 1, 6, 9}) {
        Array<u8> zc = zlib_compress(big, lvl);
        auto zd = zlib_decompress(zc, InflateOptions{.expected_size_hint = big.size()});
        TEST_CHECK(zd.is_ok() && *zd == big);
    }

    // Streaming DeflateStream (ZLIB + GZIP + Raw) with irregular chunks
    for (StreamFormat fmt : {StreamFormat::Raw, StreamFormat::Zlib, StreamFormat::Gzip}) {
        DeflateStream ds(fmt, 6);
        Array<u8> streamed;
        for (usize off = 0u; off < big.size(); off += 11111u) {
            const usize n = keel::min<usize>(big.size() - off, 11111u);
            ds.update(big.slice(off, n));
            Array<u8> part = ds.take_output();
            streamed.append(part.as_ref());
        }
        Array<u8> tail = ds.finish();
        streamed.append(tail.as_ref());

        Result<Array<u8>> dec = (fmt == StreamFormat::Raw)
            ? inflate_raw(streamed)
            : ((fmt == StreamFormat::Zlib) ? zlib_decompress(streamed) : gzip_decompress(streamed));
        TEST_CHECK(dec.is_ok() && *dec == big);
    }

    // Official BTYPE=2 vector produced by standard zlib
    const u8 dyn_vec[] = {
        0x78, 0xDA, 0x25, 0x8F, 0x89, 0x0D, 0x80, 0x30, 0x0C, 0x03, 0x67, 0xF3, 0xB3, 0xFF, 0x4C, 0xF5, 0xA5,
        0x2A, 0xA8, 0x26, 0xF1, 0x47, 0xE2, 0xB6, 0xA9, 0x76, 0x4B, 0xEE, 0x4E, 0x92, 0x1B, 0x39, 0x1B, 0x80,
        0x63, 0x8B, 0xDD, 0x40, 0x93, 0xE1, 0x42, 0xF1, 0x09, 0xA7, 0x34, 0x8A, 0x68, 0xCF, 0x50, 0x6F, 0x5F,
        0x6B, 0xC7, 0x9A, 0xC7, 0xF6, 0x0C, 0xEF, 0xBD, 0x8F, 0xD9, 0x8E, 0x39, 0x3A, 0x6C, 0xBC, 0x43, 0xCE,
        0x44, 0xA4, 0x1F, 0xBF, 0x38, 0x1B, 0x03, 0x32, 0x90, 0x41, 0x09, 0x4D, 0xCF, 0x3C, 0x57, 0x66, 0xEE,
        0x21, 0x87, 0xC6, 0x60, 0x7E, 0xE0, 0x97, 0x81, 0x30, 0x6B, 0x11, 0xB5, 0x11, 0xD4, 0x9B, 0xCD, 0x7C,
        0x3A, 0x61, 0x21, 0xBA, 0x10, 0xF7, 0x00, 0x73, 0xE3, 0x42, 0x96,
    };
    Array<u8> expected(256u);
    u32 r2 = 1u;
    for (usize i = 0u; i < 256u; ++i) {
        r2 = (r2 * 1103515245u + 12345u) & 0x7FFFFFFFu;
        expected[i] = as<u8>(65u + ((r2 >> 16u) & 3u));
    }
    auto dec_v = zlib_decompress(dyn_vec);
    TEST_CHECK(dec_v.is_ok() && *dec_v == expected);
}

void test_gzip_rfc1952() {
    const StringRef s1 = "First member of RFC 1952 GZIP stream with metadata and FHCRC!";
    const StringRef s2 = "Second concatenated GZIP member!";
    ArrayRef<u8> b1(reinterpret_cast<const u8*>(s1.data()), s1.size());
    ArrayRef<u8> b2(reinterpret_cast<const u8*>(s2.data()), s2.size());

    GzipOptions gopts{};
    gopts.level = 6;
    gopts.mtime = 1700000000u;
    gopts.os = 3u;
    gopts.filename = "report.txt";
    gopts.comment = "keel::compress gzip test";
    gopts.write_header_crc = true;

    Array<u8> gz1 = gzip_compress(b1, gopts);
    auto hdr = gzip_peek_header(gz1);
    TEST_CHECK(hdr.is_ok());
    if (hdr.is_ok()) {
        TEST_CHECK(hdr->mtime == 1700000000u);
        TEST_CHECK(hdr->os == 3u);
        TEST_CHECK(hdr->filename.as_ref() == "report.txt");
        TEST_CHECK(hdr->comment.as_ref() == "keel::compress gzip test");
    }

    auto dec1 = gzip_decompress(gz1);
    TEST_CHECK(dec1.is_ok() && *dec1 == b1);

    // Concatenated multi-member GZIP (RFC 1952 §2.2)
    Array<u8> gz2 = gzip_compress(b2, 9);
    Array<u8> multi = gz1.clone();
    multi.append(gz2.as_ref());
    auto dec_multi = gzip_decompress(multi);
    Array<u8> joined;
    joined.append(b1);
    joined.append(b2);
    TEST_CHECK(dec_multi.is_ok() && *dec_multi == joined);

    // Corruption detection: bad FHCRC, bad CRC32, bad ISIZE, decompression bomb
    Array<u8> bad_hcrc = gz1.clone();
    bad_hcrc[4] ^= 1u;
    TEST_CHECK(gzip_decompress(bad_hcrc).is_err());

    Array<u8> bad_crc = gz2.clone();
    bad_crc[bad_crc.size() - 8u] ^= 1u;
    TEST_CHECK(gzip_decompress(bad_crc).is_err());

    Array<u8> bad_isize = gz2.clone();
    bad_isize[bad_isize.size() - 1u] ^= 1u;
    TEST_CHECK(gzip_decompress(bad_isize).is_err());

    Array<u8> zeros(64u * 1024u, u8{0u});
    Array<u8> gzbomb = gzip_compress(zeros, 6);
    TEST_CHECK(gzip_decompress(gzbomb, InflateOptions{.max_output_bytes = 512u}).error().code == ErrorCode::OutOfRange);
}

void test_lz4_block_and_frame() {
    // Empty, tiny (<12B), repetitive, random, and multi-block (> 64KB) payloads
    ArrayRef<u8> empty{};
    TEST_CHECK(lz4_decompress_block(lz4_compress_block(empty)).is_ok());

    const StringRef tiny = "hi!";
    ArrayRef<u8> tiny_b(reinterpret_cast<const u8*>(tiny.data()), tiny.size());
    auto tiny_d = lz4_decompress_block(lz4_compress_block(tiny_b));
    TEST_CHECK(tiny_d.is_ok() && *tiny_d == tiny_b);

    Array<u8> big(150000u);
    u32 rng = 0x99887766u;
    for (usize i = 0u; i < big.size(); ++i) {
        if (i < 40000u) {
            big[i] = as<u8>('A' + (i % 5u));
        } else if (i < 80000u) {
            big[i] = 0x7Eu;
        } else {
            rng = rng * 1664525u + 1013904223u;
            big[i] = as<u8>(rng >> 24u);
        }
    }

    Array<u8> blk = lz4_compress_block(big);
    auto blk_dec = lz4_decompress_block(blk);
    TEST_CHECK(blk_dec.is_ok() && *blk_dec == big);

    // LZ4 Frame across block sizes & checksum combinations
    for (Lz4BlockSize bs : {Lz4BlockSize::Max64KB, Lz4BlockSize::Max256KB, Lz4BlockSize::Max4MB}) {
        Lz4FrameOptions fopts{};
        fopts.block_size = bs;
        fopts.block_checksum = (bs == Lz4BlockSize::Max64KB);
        fopts.content_checksum = true;
        fopts.write_content_size = (bs != Lz4BlockSize::Max256KB);

        Array<u8> fr = lz4_frame_compress(big, fopts);
        auto fr_dec = lz4_frame_decompress(fr);
        TEST_CHECK(fr_dec.is_ok() && *fr_dec == big);

        // Corrupted content checksum must fail
        Array<u8> bad = fr.clone();
        bad[bad.size() - 1u] ^= 1u;
        TEST_CHECK(lz4_frame_decompress(bad).is_err());

        // Corrupted header checksum must fail
        Array<u8> bad_hc = fr.clone();
        bad_hc[4] ^= 0x04u;
        TEST_CHECK(lz4_frame_decompress(bad_hc).is_err());
    }

    // Skippable frame prepended to valid LZ4 frame
    Array<u8> with_skip;
    const u8 skip_hdr[] = {0x50u, 0x2Au, 0x4Du, 0x18u, 0x04u, 0x00u, 0x00u, 0x00u, 0xDEu, 0xADu, 0xBEu, 0xEFu};
    with_skip.append(ArrayRef<u8>(skip_hdr, sizeof(skip_hdr)));
    Array<u8> fr_tiny = lz4_frame_compress(tiny_b);
    with_skip.append(fr_tiny.as_ref());
    auto skip_dec = lz4_frame_decompress(with_skip);
    TEST_CHECK(skip_dec.is_ok() && *skip_dec == tiny_b);

    // Decompression bomb cap on LZ4 Frame
    Array<u8> zeros(128u * 1024u, u8{0u});
    Array<u8> lz4_bomb = lz4_frame_compress(zeros);
    TEST_CHECK(lz4_frame_decompress(lz4_bomb, InflateOptions{.max_output_bytes = 1024u}).error().code ==
               ErrorCode::OutOfRange);
}

void test_zip_archive() {
    // Path traversal / Zip Slip safety checks
    TEST_CHECK(is_safe_zip_path("docs/readme.txt"));
    TEST_CHECK(is_safe_zip_path("a/b/c.bin"));
    TEST_CHECK(!is_safe_zip_path(""));
    TEST_CHECK(!is_safe_zip_path("/etc/passwd"));
    TEST_CHECK(!is_safe_zip_path("\\windows\\system32"));
    TEST_CHECK(!is_safe_zip_path("C:/secret.txt"));
    TEST_CHECK(!is_safe_zip_path("../escape.txt"));
    TEST_CHECK(!is_safe_zip_path("foo/../../bar.txt"));

    ZipWriter zw;
    const StringRef f1_text = "Hello ZIP world! Repeated Repeated Repeated Repeated Repeated!";
    Array<u8> f2_bin(20000u);
    for (usize i = 0u; i < f2_bin.size(); ++i) f2_bin[i] = as<u8>((i * 7u) % 251u);

    TEST_CHECK(zw.add_directory("dir") == ErrorCode::Ok);
    TEST_CHECK(zw.add_file("dir/hello.txt",
                           ArrayRef<u8>(reinterpret_cast<const u8*>(f1_text.data()), f1_text.size()), 6) ==
               ErrorCode::Ok);
    TEST_CHECK(zw.add_file("data.bin", f2_bin.as_ref(), 0) == ErrorCode::Ok);
    TEST_CHECK(zw.add_file("empty.txt", ArrayRef<u8>{}, 6) == ErrorCode::Ok);

    Array<u8> archive = zw.finish("keel::compress zip comment");
    auto zr = ZipReader::open(archive);
    TEST_CHECK(zr.is_ok());
    if (zr.is_ok()) {
        TEST_CHECK(zr->entry_count() == 4u);
        TEST_CHECK(zr->comment() == "keel::compress zip comment");
        TEST_CHECK(zr->entry(0u).is_directory());

        auto ex1 = zr->extract("dir/hello.txt");
        TEST_CHECK(ex1.is_ok() &&
                   *ex1 == ArrayRef<u8>(reinterpret_cast<const u8*>(f1_text.data()), f1_text.size()));
        auto ex2 = zr->extract("data.bin");
        TEST_CHECK(ex2.is_ok() && *ex2 == f2_bin);
        auto ex3 = zr->extract("empty.txt");
        TEST_CHECK(ex3.is_ok() && ex3->empty());
        TEST_CHECK(zr->extract("missing.txt").error().code == ErrorCode::NotFound);

        // Bomb cap
        TEST_CHECK(zr->extract("data.bin", InflateOptions{.max_output_bytes = 100u}).error().code ==
                   ErrorCode::OutOfRange);
    }

    // Corrupted payload CRC must fail extraction
    Array<u8> corrupt = archive.clone();
    corrupt[archive.size() / 2u] ^= 0xFFu;
    auto zr_bad = ZipReader::open(corrupt);
    if (zr_bad.is_ok()) {
        bool any_failed = false;
        for (usize i = 0u; i < zr_bad->entry_count(); ++i) {
            if (zr_bad->extract(i).is_err()) any_failed = true;
        }
        TEST_CHECK(any_failed);
    }
}

void test_safety_and_fuzz_resilience() {
    // 1. Decompression bomb cap (OutOfRange)
    Array<u8> zeros(64u * 1024u, u8{0u});
    Array<u8> bomb = zlib_compress(zeros, 6);
    auto capped = zlib_decompress(bomb, InflateOptions{.max_output_bytes = 1024u});
    TEST_CHECK(capped.is_err() && capped.error().code == ErrorCode::OutOfRange);

    // 2. Truncated ZLIB stream & bad header/trailer
    TEST_CHECK(zlib_decompress(bomb.slice(0u, 3u)).error().code == ErrorCode::EndOfFile);
    TEST_CHECK(zlib_decompress(bomb.slice(0u, bomb.size() - 5u)).error().code == ErrorCode::EndOfFile);

    Array<u8> bad_hdr = bomb.clone();
    bad_hdr[0] ^= 0x01u;
    TEST_CHECK(zlib_decompress(bad_hdr).error().code == ErrorCode::InvalidData);

    Array<u8> fdict_hdr = bomb.clone();
    fdict_hdr[0] = 0x78u;
    fdict_hdr[1] = 0x20u; // FDICT=1, ((0x78 << 8) + 0x20) % 31 == 0
    TEST_CHECK(zlib_decompress(fdict_hdr).error().code == ErrorCode::NotSupported);

    Array<u8> bad_adler = bomb.clone();
    bad_adler[bad_adler.size() - 1u] ^= 0xFFu;
    TEST_CHECK(zlib_decompress(bad_adler).error().code == ErrorCode::InvalidData);

    const u8 bad_btype[] = {0x07u};
    TEST_CHECK(inflate_raw(bad_btype).error().code == ErrorCode::InvalidData);

    // 3. Deterministic fuzzing of all decoders with garbage / truncated inputs (ASan safety)
    u32 rng = 0xDEADBEEFu;
    InflateOptions cap{};
    cap.max_output_bytes = 64u * 1024u;
    for (usize iter = 0u; iter < 120u; ++iter) {
        const usize n = iter % 97u;
        Array<u8> junk(n);
        for (usize i = 0u; i < n; ++i) {
            rng = rng * 1664525u + 1013904223u;
            junk[i] = as<u8>(rng >> 24u);
        }
        (void)inflate_raw(junk, cap);
        (void)zlib_decompress(junk, cap);
        (void)gzip_decompress(junk, cap);
        (void)lz4_decompress_block(junk, cap.max_output_bytes);
        (void)lz4_frame_decompress(junk, cap);
        auto zr = ZipReader::open(junk);
        if (zr.is_ok()) {
            for (usize e = 0u; e < zr->entry_count(); ++e) {
                (void)zr->extract(e, cap);
            }
        }
    }
    ++g_tests_passed; // Reached cleanly without UB/crash

    // 4. Custom Arena allocator routing
    Arena custom_arena(1024u * 1024u);
    const usize before = custom_arena.used();
    Array<u8> arena_comp = zlib_compress(zeros.slice(0u, 512u), 6, custom_arena.allocator());
    TEST_CHECK(custom_arena.used() > before);
    auto arena_dec = zlib_decompress(arena_comp, InflateOptions{.allocator = custom_arena.allocator()});
    TEST_CHECK(arena_dec.is_ok() && arena_dec->size() == 512u);
    TEST_CHECK(arena_dec->allocator() == custom_arena.allocator());
}

} // namespace

int main(int argc, char** argv) {
    // CLI harness for tests/verify_reference.py:
    //   test_compress --checksums <in_file>
    //   test_compress --deflate-enc <level> <in_file> <out_file>
    //   test_compress --deflate-dec <in_file> <out_file>
    //   test_compress --zlib-enc <level> <in_file> <out_file>
    //   test_compress --zlib-dec <in_file> <out_file>
    //   test_compress --gzip-enc <level> <in_file> <out_file>
    //   test_compress --gzip-dec <in_file> <out_file>
    //   test_compress --lz4-frame-enc <block_id> <blk_crc> <cnt_crc> <in_file> <out_file>
    //   test_compress --lz4-frame-dec <in_file> <out_file>
    //   test_compress --zip-extract <zip_file> <entry_name> <out_file>
    //   test_compress --zip-create <zip_file> <entry_name> <level> <in_file>
    if (argc >= 2) {
        const StringRef cmd(argv[1]);
        if (cmd == "--checksums" && argc == 3) {
            auto in = fs_read_file(StringRef(argv[2]));
            if (in.is_err()) return 2;
            keel::println("{:08x} {:08x} {:08x} {:08x} {:016x}",
                          crc32(*in), crc32c(*in), adler32(*in), xxhash32(*in, 0u), xxhash64(*in, 0u));
            return 0;
        }
        if ((cmd == "--deflate-enc" || cmd == "--zlib-enc" || cmd == "--gzip-enc") && argc == 5) {
            auto lvl = parse_i64(StringRef(argv[2]));
            auto in = fs_read_file(StringRef(argv[3]));
            if (lvl.is_err() || in.is_err()) return 2;
            const i32 level = as<i32>(lvl.value());
            Array<u8> out = (cmd == "--deflate-enc")
                ? deflate_raw(*in, level)
                : ((cmd == "--zlib-enc") ? zlib_compress(*in, level) : gzip_compress(*in, level));
            return fs_write_file(StringRef(argv[4]), out.as_ref()).is_ok() ? 0 : 3;
        }
        if ((cmd == "--deflate-dec" || cmd == "--zlib-dec" || cmd == "--gzip-dec" || cmd == "--lz4-frame-dec") &&
            argc == 4) {
            auto in = fs_read_file(StringRef(argv[2]));
            if (in.is_err()) return 2;
            Result<Array<u8>> out = (cmd == "--deflate-dec")
                ? inflate_raw(*in)
                : ((cmd == "--zlib-dec")
                       ? zlib_decompress(*in)
                       : ((cmd == "--gzip-dec") ? gzip_decompress(*in) : lz4_frame_decompress(*in)));
            if (out.is_err()) return 4;
            return fs_write_file(StringRef(argv[3]), out->as_ref()).is_ok() ? 0 : 3;
        }
        if (cmd == "--lz4-frame-enc" && argc == 7) {
            auto bid = parse_u64(StringRef(argv[2]));
            auto bcrc = parse_u64(StringRef(argv[3]));
            auto ccrc = parse_u64(StringRef(argv[4]));
            auto in = fs_read_file(StringRef(argv[5]));
            if (bid.is_err() || bcrc.is_err() || ccrc.is_err() || in.is_err()) return 2;
            Lz4FrameOptions opts{};
            opts.block_size = static_cast<Lz4BlockSize>(bid.value());
            opts.block_checksum = (bcrc.value() != 0u);
            opts.content_checksum = (ccrc.value() != 0u);
            Array<u8> out = lz4_frame_compress(*in, opts);
            return fs_write_file(StringRef(argv[6]), out.as_ref()).is_ok() ? 0 : 3;
        }
        if (cmd == "--zip-extract" && argc == 5) {
            auto in = fs_read_file(StringRef(argv[2]));
            auto ename = fs_read_text(StringRef(argv[3]));
            if (in.is_err() || ename.is_err()) return 2;
            auto zr = ZipReader::open(*in);
            if (zr.is_err()) return 4;
            auto ex = zr->extract(ename->as_ref());
            if (ex.is_err()) return 5;
            return fs_write_file(StringRef(argv[4]), ex->as_ref()).is_ok() ? 0 : 3;
        }
        if (cmd == "--zip-create" && argc == 6) {
            auto lvl = parse_i64(StringRef(argv[4]));
            auto ename = fs_read_text(StringRef(argv[3]));
            auto in = fs_read_file(StringRef(argv[5]));
            if (lvl.is_err() || ename.is_err() || in.is_err()) return 2;
            ZipWriter zw;
            if (zw.add_file(ename->as_ref(), *in, as<i32>(lvl.value())) != ErrorCode::Ok) return 4;
            Array<u8> out = zw.finish("keel-zip");
            return fs_write_file(StringRef(argv[2]), out.as_ref()).is_ok() ? 0 : 3;
        }
        return 2;
    }

    test_checksums();
    test_deflate_zlib_and_streaming();
    test_gzip_rfc1952();
    test_lz4_block_and_frame();
    test_zip_archive();
    test_safety_and_fuzz_resilience();

    if (g_tests_failed != 0) {
        keel::eprintln("{} test check(s) FAILED ({} passed)", g_tests_failed, g_tests_passed);
        return 1;
    }
    keel::println("All {} keel::compress test checks passed.", g_tests_passed);
    return 0;
}
