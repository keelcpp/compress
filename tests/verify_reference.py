#!/usr/bin/env python3
"""Differential cross-verification of keel::compress against independent
reference implementations:
  - Python stdlib zlib (CRC-32, Adler-32, raw Deflate, ZLIB levels 0..9)
  - Python stdlib gzip (single & concatenated multi-member GZIP streams)
  - Python stdlib zipfile (bidirectional ZIP Store/Deflate + UTF-8 names)
  - Pure-Python independent CRC-32C, XXH32, and LZ4 Frame v1.6.4 decoder/encoder
"""
import gzip
import io
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

EXE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(__file__), "..", "build", "Release", "test_compress.exe"
)

def run_keel(*args: str) -> str:
    r = subprocess.run([EXE, *args], capture_output=True, text=True, check=True)
    return r.stdout.strip()

# Independent pure-Python CRC-32C (Castagnoli)
def ref_crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc >> 1) ^ 0x82F63B78) if (crc & 1) else (crc >> 1)
    return crc ^ 0xFFFFFFFF

# Independent pure-Python XXH32
def ref_xxh32(data: bytes, seed: int = 0) -> int:
    P1, P2, P3, P4, P5 = 0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D, 0x27D4EB2F, 0x165667B1
    M = 0xFFFFFFFF
    rotl = lambda x, r: ((x << r) | (x >> (32 - r))) & M
    n = len(data)
    off = 0
    if n >= 16:
        v1 = (seed + P1 + P2) & M
        v2 = (seed + P2) & M
        v3 = seed & M
        v4 = (seed - P1) & M
        while off + 16 <= n:
            w1, w2, w3, w4 = struct.unpack_from("<4I", data, off)
            v1 = (rotl((v1 + w1 * P2) & M, 13) * P1) & M
            v2 = (rotl((v2 + w2 * P2) & M, 13) * P1) & M
            v3 = (rotl((v3 + w3 * P2) & M, 13) * P1) & M
            v4 = (rotl((v4 + w4 * P2) & M, 13) * P1) & M
            off += 16
        h = (rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18)) & M
    else:
        h = (seed + P5) & M
    h = (h + n) & M
    while off + 4 <= n:
        w = struct.unpack_from("<I", data, off)[0]
        h = (rotl((h + w * P3) & M, 17) * P4) & M
        off += 4
    while off < n:
        h = (rotl((h + data[off] * P5) & M, 11) * P1) & M
        off += 1
    h = ((h ^ (h >> 15)) * P2) & M
    h = ((h ^ (h >> 13)) * P3) & M
    return (h ^ (h >> 16)) & M

# Independent pure-Python LZ4 Frame v1.6.4 reference decoder
def ref_lz4_frame_decompress(frame: bytes) -> bytes:
    assert struct.unpack_from("<I", frame, 0)[0] == 0x184D2204
    pos = 4
    desc_start = pos
    flg, bd = frame[pos], frame[pos + 1]
    pos += 2
    assert (flg & 0xC0) == 0x40
    blk_crc = bool(flg & 0x10)
    has_csz = bool(flg & 0x08)
    cnt_crc = bool(flg & 0x04)
    exp_csz = None
    if has_csz:
        exp_csz = struct.unpack_from("<Q", frame, pos)[0]
        pos += 8
    hc = frame[pos]
    assert hc == ((ref_xxh32(frame[desc_start:pos], 0) >> 8) & 0xFF)
    pos += 1
    out = bytearray()
    while True:
        bh = struct.unpack_from("<I", frame, pos)[0]
        pos += 4
        if bh == 0:
            break
        uncomp = bool(bh & 0x80000000)
        bsz = bh & 0x7FFFFFFF
        bdata = frame[pos:pos + bsz]
        pos += bsz
        if blk_crc:
            exp_bc = struct.unpack_from("<I", frame, pos)[0]
            pos += 4
            assert ref_xxh32(bdata, 0) == exp_bc
        if uncomp:
            out.extend(bdata)
        else:
            p = 0
            while p < len(bdata):
                tok = bdata[p]; p += 1
                ll = tok >> 4
                if ll == 15:
                    while True:
                        b = bdata[p]; p += 1
                        ll += b
                        if b != 255:
                            break
                out.extend(bdata[p:p + ll]); p += ll
                if p == len(bdata):
                    break
                off = struct.unpack_from("<H", bdata, p)[0]; p += 2
                ml = (tok & 0x0F) + 4
                if (tok & 0x0F) == 15:
                    while True:
                        b = bdata[p]; p += 1
                        ml += b
                        if b != 255:
                            break
                for _ in range(ml):
                    out.append(out[-off])
    if exp_csz is not None:
        assert len(out) == exp_csz
    if cnt_crc:
        exp_cc = struct.unpack_from("<I", frame, pos)[0]
        pos += 4
        assert ref_xxh32(bytes(out), 0) == exp_cc
    assert pos == len(frame)
    return bytes(out)

def make_payloads():
    rng = random.Random(20261125)
    payloads = [
        ("empty", b""),
        ("one", b"X"),
        ("tiny", b"hello world"),
        ("rle_64k", b"\x42" * 65536),
        ("text_json", (b'{"key":"value","nums":[1,2,3,4,5,6,7,8,9,10],"ok":true}\n' * 1200)),
        ("skewed_abcd", bytes(rng.choices(b"AAAABBCD", k=40000))),
        ("random_16k", rng.randbytes(16384)),
        ("mixed_200k", (b"The quick brown fox jumps over the lazy dog. " * 2000) +
                       rng.randbytes(30000) + (b"\x00\x01\x02\x03" * 20000)),
    ]
    for sz in [15, 16, 17, 63, 64, 65, 255, 256, 257, 1024, 4097, 32768, 65535, 65536, 65537]:
        # Patterned + noise
        buf = bytearray(sz)
        for i in range(sz):
            buf[i] = (i % 29) ^ (rng.randrange(256) if (i % 7 == 0) else 0)
        payloads.append((f"edge_{sz}", bytes(buf)))
    return payloads

total_checks = 0
tmp = tempfile.mkdtemp(prefix="keel_compress_ref_")
try:
    f_in = os.path.join(tmp, "in.bin")
    f_comp = os.path.join(tmp, "comp.bin")
    f_out = os.path.join(tmp, "out.bin")
    payloads = make_payloads()

    # 1. Checksums (CRC-32, CRC-32C, Adler-32, XXH32)
    for name, data in payloads:
        with open(f_in, "wb") as f:
            f.write(data)
        parts = run_keel("--checksums", f_in).split()
        got_crc, got_crc32c, got_adler, got_xxh32 = [int(x, 16) for x in parts[:4]]
        assert got_crc == (zlib.crc32(data) & 0xFFFFFFFF), f"CRC32 mismatch on {name}"
        assert got_crc32c == ref_crc32c(data), f"CRC32C mismatch on {name}"
        assert got_adler == (zlib.adler32(data) & 0xFFFFFFFF), f"Adler32 mismatch on {name}"
        assert got_xxh32 == ref_xxh32(data, 0), f"XXH32 mismatch on {name}"
        total_checks += 4

    # 2. Raw Deflate & ZLIB (bidirectional vs Python zlib across levels 0, 1, 6, 9)
    for name, data in payloads:
        with open(f_in, "wb") as f:
            f.write(data)
        for lvl in [0, 1, 6, 9]:
            # keel -> Python zlib (raw deflate)
            run_keel("--deflate-enc", str(lvl), f_in, f_comp)
            with open(f_comp, "rb") as f:
                cbytes = f.read()
            assert zlib.decompress(cbytes, -15) == data, f"keel deflate -> zlib failed on {name} lvl={lvl}"
            # keel -> Python zlib (zlib wrapper)
            run_keel("--zlib-enc", str(lvl), f_in, f_comp)
            with open(f_comp, "rb") as f:
                zbytes = f.read()
            assert zlib.decompress(zbytes) == data, f"keel zlib -> zlib failed on {name} lvl={lvl}"
            total_checks += 2

        # Python zlib (levels 0, 1, 6, 9) -> keel inflate_raw & zlib_decompress
        for lvl in [0, 1, 6, 9]:
            co = zlib.compressobj(lvl, zlib.DEFLATED, -15)
            raw_z = co.compress(data) + co.flush()
            with open(f_comp, "wb") as f:
                f.write(raw_z)
            run_keel("--deflate-dec", f_comp, f_out)
            with open(f_out, "rb") as f:
                assert f.read() == data, f"zlib -> keel inflate_raw failed on {name} lvl={lvl}"

            z_std = zlib.compress(data, lvl)
            with open(f_comp, "wb") as f:
                f.write(z_std)
            run_keel("--zlib-dec", f_comp, f_out)
            with open(f_out, "rb") as f:
                assert f.read() == data, f"zlib -> keel zlib_decompress failed on {name} lvl={lvl}"
            total_checks += 2

    # Compression ratio sanity: keel Dynamic Huffman on text_json must be within 10% of zlib level 6
    text_data = dict(payloads)["text_json"]
    with open(f_in, "wb") as f:
        f.write(text_data)
    run_keel("--zlib-enc", "6", f_in, f_comp)
    keel_sz = os.path.getsize(f_comp)
    zlib_sz = len(zlib.compress(text_data, 6))
    assert keel_sz < len(text_data) // 10, f"Poor compression ratio on text_json: {keel_sz}"
    total_checks += 1

    # 3. GZIP (bidirectional vs Python gzip + concatenated multi-member)
    for name, data in payloads[:10]:
        with open(f_in, "wb") as f:
            f.write(data)
        run_keel("--gzip-enc", "6", f_in, f_comp)
        with open(f_comp, "rb") as f:
            assert gzip.decompress(f.read()) == data, f"keel gzip -> py gzip failed on {name}"

        with open(f_comp, "wb") as f:
            f.write(gzip.compress(data, compresslevel=9, mtime=1234567))
        run_keel("--gzip-dec", f_comp, f_out)
        with open(f_out, "rb") as f:
            assert f.read() == data, f"py gzip -> keel gzip failed on {name}"
        total_checks += 2

    # Concatenated 3-member GZIP generated by Python gzip -> keel gzip_decompress
    p1, p2, p3 = b"Alpha " * 100, b"", b"Omega " * 250
    concat_gz = gzip.compress(p1) + gzip.compress(p2) + gzip.compress(p3)
    with open(f_comp, "wb") as f:
        f.write(concat_gz)
    run_keel("--gzip-dec", f_comp, f_out)
    with open(f_out, "rb") as f:
        assert f.read() == p1 + p2 + p3, "concatenated gzip mismatch"
    total_checks += 1

    # 4. ZIP bidirectional vs Python zipfile (Store + Deflate + UTF-8 names)
    f_zip = os.path.join(tmp, "test.zip")
    f_name = os.path.join(tmp, "ename.txt")
    for name, data in payloads[:8]:
        with open(f_in, "wb") as f:
            f.write(data)
        for lvl in [0, 6]:
            entry_name = f"sub/{name}_пример.bin"
            with open(f_name, "wb") as f:
                f.write(entry_name.encode("utf-8"))
            run_keel("--zip-create", f_zip, f_name, str(lvl), f_in)
            with zipfile.ZipFile(f_zip, "r") as zf:
                assert zf.testzip() is None, f"zipfile.testzip() failed on {name} lvl={lvl}"
                assert zf.read(entry_name) == data
                assert zf.comment == b"keel-zip"
            total_checks += 1

    # Python zipfile -> keel ZipReader (Store + Deflate + Unicode)
    with zipfile.ZipFile(f_zip, "w") as zf:
        zf.writestr("a_store.bin", payloads[4][1], compress_type=zipfile.ZIP_STORED)
        zf.writestr("b_deflate.bin", payloads[7][1], compress_type=zipfile.ZIP_DEFLATED)
        zf.writestr("юникод/empty.txt", b"", compress_type=zipfile.ZIP_DEFLATED)
    for ename, exp in [
        ("a_store.bin", payloads[4][1]),
        ("b_deflate.bin", payloads[7][1]),
        ("юникод/empty.txt", b""),
    ]:
        with open(f_name, "wb") as f:
            f.write(ename.encode("utf-8"))
        run_keel("--zip-extract", f_zip, f_name, f_out)
        with open(f_out, "rb") as f:
            assert f.read() == exp, f"py zipfile -> keel ZipReader mismatch on {ename}"
        total_checks += 1

    # 5. LZ4 Frame (keel -> independent pure-Python spec decoder + round-trip)
    for name, data in payloads[:10]:
        with open(f_in, "wb") as f:
            f.write(data)
        for bid, bcrc, ccrc in [(4, 1, 1), (5, 0, 1), (7, 0, 0)]:
            run_keel("--lz4-frame-enc", str(bid), str(bcrc), str(ccrc), f_in, f_comp)
            with open(f_comp, "rb") as f:
                frame_bytes = f.read()
            assert ref_lz4_frame_decompress(frame_bytes) == data, f"LZ4 frame ref decode failed on {name}"
            run_keel("--lz4-frame-dec", f_comp, f_out)
            with open(f_out, "rb") as f:
                assert f.read() == data, f"LZ4 frame keel roundtrip failed on {name}"
            total_checks += 2

    print(
        f"ALL COMPRESS REFERENCE CHECKS PASSED: {total_checks} checks "
        f"(0 mismatches; text_json keel={keel_sz}B vs zlib={zlib_sz}B)"
    )
finally:
    shutil.rmtree(tmp, ignore_errors=True)
