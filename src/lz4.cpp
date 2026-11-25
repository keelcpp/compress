#include "keel/compress/lz4.h"

#include "keel/arena.h"
#include "keel/compress/checksum.h"
#include "keel/memory.h"

namespace keel::compress {

namespace {

constexpr u32 kLz4FrameMagic = 0x184D2204u;
constexpr u32 kLz4SkipMagicMask = 0xFFFFFFF0u;
constexpr u32 kLz4SkipMagicBase = 0x184D2A50u;

constexpr usize kMinMatch = 4u;
constexpr usize kLastLiterals = 5u;
constexpr usize kMfLimit = 12u;
constexpr usize kMaxDist = 65535u;
constexpr u32 kHashLog = 14u;
constexpr usize kHashTableSize = usize{1u} << kHashLog;

constexpr u16 load_le16(const u8* p) noexcept {
    return as<u16>(as<u16>(p[0]) | (as<u16>(p[1]) << 8u));
}

constexpr u32 load_le32(const u8* p) noexcept {
    return as<u32>(p[0]) | (as<u32>(p[1]) << 8u) | (as<u32>(p[2]) << 16u) | (as<u32>(p[3]) << 24u);
}

constexpr u64 load_le64(const u8* p) noexcept {
    return as<u64>(load_le32(p)) | (as<u64>(load_le32(p + 4u)) << 32u);
}

void push_le16(Array<u8>& out, u16 v) {
    out.push_back(as<u8>(v & 0xFFu));
    out.push_back(as<u8>((v >> 8u) & 0xFFu));
}

void push_le32(Array<u8>& out, u32 v) {
    out.push_back(as<u8>(v & 0xFFu));
    out.push_back(as<u8>((v >> 8u) & 0xFFu));
    out.push_back(as<u8>((v >> 16u) & 0xFFu));
    out.push_back(as<u8>((v >> 24u) & 0xFFu));
}

void push_le64(Array<u8>& out, u64 v) {
    push_le32(out, as<u32>(v & 0xFFFFFFFFull));
    push_le32(out, as<u32>(v >> 32u));
}

inline usize lz4_hash4(u32 v) noexcept {
    return as<usize>((v * 2654435761u) >> (32u - kHashLog));
}

void write_extra_len(Array<u8>& out, usize len) {
    while (len >= 255u) {
        out.push_back(255u);
        len -= 255u;
    }
    out.push_back(as<u8>(len));
}

usize block_max_bytes(Lz4BlockSize bs) noexcept {
    switch (bs) {
    case Lz4BlockSize::Max64KB:  return 64u * 1024u;
    case Lz4BlockSize::Max256KB: return 256u * 1024u;
    case Lz4BlockSize::Max1MB:   return 1024u * 1024u;
    case Lz4BlockSize::Max4MB:   return 4u * 1024u * 1024u;
    }
    return 4u * 1024u * 1024u;
}

ErrorCode lz4_decompress_block_into(ArrayRef<u8> src, Array<u8>& out,
                                      usize max_output_bytes, usize dict_base_size) {
    const u8* ip = src.data();
    const usize src_len = src.size();
    usize pos = 0u;
    const usize base_size = dict_base_size;

    auto exceeds_cap = [&](usize add_bytes) noexcept -> bool {
        if (max_output_bytes == 0u) return false;
        return add_bytes > max_output_bytes || out.size() > (max_output_bytes - add_bytes);
    };

    while (pos < src_len) {
        const u8 token = ip[pos++];
        usize lit_len = as<usize>(token >> 4u);
        if (lit_len == 15u) {
            u8 b = 255u;
            while (b == 255u) {
                if (pos >= src_len) [[unlikely]] return ErrorCode::EndOfFile;
                b = ip[pos++];
                if (lit_len > Limits<usize>::kMax - as<usize>(b)) [[unlikely]] return ErrorCode::OutOfRange;
                lit_len += as<usize>(b);
            }
        }

        if (lit_len > src_len - pos) [[unlikely]] {
            return ErrorCode::EndOfFile;
        }
        if (exceeds_cap(lit_len)) [[unlikely]] {
            return ErrorCode::OutOfRange;
        }
        if (lit_len > 0u) {
            out.append(ArrayRef<u8>(ip + pos, lit_len));
            pos += lit_len;
        }

        // End of block: last sequence contains literals only (no offset/match)
        if (pos == src_len) {
            break;
        }

        if (src_len - pos < 2u) [[unlikely]] {
            return ErrorCode::EndOfFile;
        }
        const usize offset = as<usize>(load_le16(ip + pos));
        pos += 2u;
        if (offset == 0u || offset > (out.size() - base_size)) [[unlikely]] {
            return ErrorCode::InvalidData;
        }

        usize match_len = as<usize>(token & 0x0Fu) + kMinMatch;
        if ((token & 0x0Fu) == 15u) {
            u8 b = 255u;
            while (b == 255u) {
                if (pos >= src_len) [[unlikely]] return ErrorCode::EndOfFile;
                b = ip[pos++];
                if (match_len > Limits<usize>::kMax - as<usize>(b)) [[unlikely]] return ErrorCode::OutOfRange;
                match_len += as<usize>(b);
            }
        }

        if (exceeds_cap(match_len)) [[unlikely]] {
            return ErrorCode::OutOfRange;
        }

        const usize old_size = out.size();
        out.resize(old_size + match_len);
        u8* dst = out.data() + old_size;
        const u8* copy_src = dst - offset;
        if (offset >= match_len) {
            mem_copy(dst, copy_src, match_len);
        } else if (offset == 1u) {
            mem_set(dst, *copy_src, match_len);
        } else {
            for (usize k = 0u; k < match_len; ++k) {
                dst[k] = copy_src[k];
            }
        }
    }

    return ErrorCode::Ok;
}

} // namespace

// ---------------------------------------------------------------------------
// LZ4 Raw Block
// ---------------------------------------------------------------------------
Array<u8> lz4_compress_block(ArrayRef<u8> src, Allocator* alloc) {
    Allocator* dst_alloc = alloc ? alloc : default_allocator();
    Array<u8> out(dst_alloc);
    const usize len = src.size();
    if (len == 0u) return out;

    out.reserve(keel::min<usize>(lz4_compress_bound(len), len + 64u));
    const u8* ip = src.data();

    if (len < kMfLimit) {
        const u8 tok = as<u8>((len < 15u ? len : 15u) << 4u);
        out.push_back(tok);
        if (len >= 15u) write_extra_len(out, len - 15u);
        out.append(src);
        return out;
    }

    ArenaTemp scratch = get_scratch(dst_alloc);
    usize* table = scratch.arena().alloc_array<usize>(kHashTableSize);
    mem_zero(table, kHashTableSize * sizeof(usize));

    const usize mf_limit = len - kMfLimit;
    const usize match_limit = len - kLastLiterals;

    usize anchor = 0u;
    usize pos = 0u;
    // Seed first position
    table[lz4_hash4(load_le32(ip))] = 0u;
    ++pos;

    while (pos <= mf_limit) {
        const u32 cur_val = load_le32(ip + pos);
        const usize h = lz4_hash4(cur_val);
        const usize ref = table[h];
        table[h] = pos;

        const usize dist = pos - ref;
        if (dist == 0u || dist > kMaxDist || load_le32(ip + ref) != cur_val) {
            ++pos;
            continue;
        }

        // Extend match forward
        usize match_len = kMinMatch;
        while (pos + match_len < match_limit && ip[pos + match_len] == ip[ref + match_len]) {
            ++match_len;
        }

        // Emit sequence: token + extra lit len + literals + le16 offset + extra match len
        const usize lit_len = pos - anchor;
        const usize ml_code = match_len - kMinMatch;
        const u8 tok = as<u8>(((lit_len < 15u ? lit_len : 15u) << 4u) |
                              (ml_code < 15u ? ml_code : 15u));
        out.push_back(tok);
        if (lit_len >= 15u) write_extra_len(out, lit_len - 15u);
        if (lit_len > 0u) out.append(ArrayRef<u8>(ip + anchor, lit_len));
        push_le16(out, as<u16>(dist));
        if (ml_code >= 15u) write_extra_len(out, ml_code - 15u);

        pos += match_len;
        anchor = pos;
        if (pos > mf_limit) break;

        // Update hash at pos - 2 for better chaining
        table[lz4_hash4(load_le32(ip + pos - 2u))] = pos - 2u;
    }

    // Emit final literals (always required when anchor < len)
    const usize last_lits = len - anchor;
    const u8 last_tok = as<u8>((last_lits < 15u ? last_lits : 15u) << 4u);
    out.push_back(last_tok);
    if (last_lits >= 15u) write_extra_len(out, last_lits - 15u);
    if (last_lits > 0u) out.append(ArrayRef<u8>(ip + anchor, last_lits));
    return out;
}

Result<Array<u8>> lz4_decompress_block(ArrayRef<u8> src, usize max_output_bytes, Allocator* alloc) {
    Allocator* dst_alloc = alloc ? alloc : default_allocator();
    Array<u8> out(dst_alloc);
    const ErrorCode ec = lz4_decompress_block_into(src, out, max_output_bytes, 0u);
    if (ec != ErrorCode::Ok) [[unlikely]] return ec;
    return out;
}

// ---------------------------------------------------------------------------
// LZ4 Frame Format (Official Spec v1.6.4)
// ---------------------------------------------------------------------------
Array<u8> lz4_frame_compress(ArrayRef<u8> src, const Lz4FrameOptions& opts) {
    Allocator* alloc = opts.allocator ? opts.allocator : default_allocator();
    Array<u8> out(alloc);
    out.reserve(src.size() + 64u);

    // 1. Magic number
    push_le32(out, kLz4FrameMagic);

    // 2. Frame descriptor: FLG, BD, optional ContentSize (8B), HC (1B)
    // Version = 01 (bits 7..6), B.Indep = 1 (bit 5)
    u8 flg = 0x60u;
    if (opts.block_checksum) flg = as<u8>(flg | 0x10u);
    if (opts.write_content_size) flg = as<u8>(flg | 0x08u);
    if (opts.content_checksum) flg = as<u8>(flg | 0x04u);

    const u8 bd = as<u8>((as<u8>(opts.block_size) & 0x07u) << 4u);
    const usize desc_start = out.size();
    out.push_back(flg);
    out.push_back(bd);
    if (opts.write_content_size) {
        push_le64(out, as<u64>(src.size()));
    }
    const u8 hc = as<u8>((xxhash32(out.as_ref().slice(desc_start), 0u) >> 8u) & 0xFFu);
    out.push_back(hc);

    // 3. Data blocks
    const usize max_blk = block_max_bytes(opts.block_size);
    usize pos = 0u;
    while (pos < src.size()) {
        const usize chunk_len = keel::min<usize>(src.size() - pos, max_blk);
        const ArrayRef<u8> chunk = src.slice(pos, chunk_len);
        Array<u8> comp = lz4_compress_block(chunk, alloc);

        if (comp.size() < chunk_len) {
            push_le32(out, as<u32>(comp.size()));
            out.append(comp.as_ref());
            if (opts.block_checksum) {
                push_le32(out, xxhash32(comp.as_ref(), 0u));
            }
        } else {
            // Store uncompressed block (highest bit 0x80000000 set)
            push_le32(out, as<u32>(chunk_len) | 0x80000000u);
            out.append(chunk);
            if (opts.block_checksum) {
                push_le32(out, xxhash32(chunk, 0u));
            }
        }
        pos += chunk_len;
    }

    // 4. EndMark (4 zero bytes) + optional Content Checksum (XXH32)
    push_le32(out, 0u);
    if (opts.content_checksum) {
        push_le32(out, xxhash32(src, 0u));
    }
    return out;
}

Result<Array<u8>> lz4_frame_decompress(ArrayRef<u8> src, const InflateOptions& opts) {
    if (src.size() < 4u) [[unlikely]] {
        return ErrorCode::EndOfFile;
    }

    Allocator* alloc = opts.allocator ? opts.allocator : default_allocator();
    Array<u8> out(alloc);
    usize pos = 0u;
    bool decoded_any_frame = false;

    while (pos < src.size()) {
        if (src.size() - pos < 4u) [[unlikely]] {
            return ErrorCode::EndOfFile;
        }
        const u32 magic = load_le32(src.data() + pos);
        pos += 4u;

        // Skippable frame (0x184D2A50 .. 0x184D2A5F)
        if ((magic & kLz4SkipMagicMask) == kLz4SkipMagicBase) {
            if (src.size() - pos < 4u) [[unlikely]] return ErrorCode::EndOfFile;
            const usize skip_len = as<usize>(load_le32(src.data() + pos));
            pos += 4u;
            if (src.size() - pos < skip_len) [[unlikely]] return ErrorCode::EndOfFile;
            pos += skip_len;
            continue;
        }

        if (magic != kLz4FrameMagic) [[unlikely]] {
            return ErrorCode::InvalidData;
        }
        decoded_any_frame = true;

        if (src.size() - pos < 3u) [[unlikely]] {
            return ErrorCode::EndOfFile;
        }
        const usize desc_start = pos;
        const u8 flg = src[pos++];
        const u8 bd = src[pos++];

        // Check version == 01, reserved bits == 0
        if ((flg & 0xC0u) != 0x40u || (flg & 0x02u) != 0u) [[unlikely]] {
            return ErrorCode::InvalidData;
        }
        if ((bd & 0x8Fu) != 0u) [[unlikely]] {
            return ErrorCode::InvalidData;
        }
        const u8 block_id = as<u8>((bd >> 4u) & 0x07u);
        if (block_id < 4u || block_id > 7u) [[unlikely]] {
            return ErrorCode::InvalidData;
        }
        const usize max_blk = block_max_bytes(static_cast<Lz4BlockSize>(block_id));

        const bool block_indep = (flg & 0x20u) != 0u;
        const bool block_checksum = (flg & 0x10u) != 0u;
        const bool has_content_size = (flg & 0x08u) != 0u;
        const bool content_checksum = (flg & 0x04u) != 0u;
        const bool has_dict_id = (flg & 0x01u) != 0u;

        u64 expected_content_size = 0u;
        if (has_content_size) {
            if (src.size() - pos < 8u) [[unlikely]] return ErrorCode::EndOfFile;
            expected_content_size = load_le64(src.data() + pos);
            pos += 8u;
            if (opts.max_output_bytes > 0u &&
                (out.size() > opts.max_output_bytes ||
                 expected_content_size > as<u64>(opts.max_output_bytes - out.size()))) [[unlikely]] {
                return ErrorCode::OutOfRange;
            }
        }
        if (has_dict_id) {
            if (src.size() - pos < 4u) [[unlikely]] return ErrorCode::EndOfFile;
            return ErrorCode::NotSupported;
        }
        if (src.size() - pos < 1u) [[unlikely]] return ErrorCode::EndOfFile;
        const u8 expected_hc = src[pos];
        const u8 actual_hc = as<u8>((xxhash32(src.slice(desc_start, pos - desc_start), 0u) >> 8u) & 0xFFu);
        ++pos;
        if (expected_hc != actual_hc) [[unlikely]] {
            return ErrorCode::InvalidData;
        }

        const usize frame_out_start = out.size();
        if (has_content_size && expected_content_size <= 16ULL * 1024u * 1024u) {
            out.reserve(frame_out_start + as<usize>(expected_content_size));
        }

        // Decode data blocks until EndMark (0x00000000)
        while (true) {
            if (src.size() - pos < 4u) [[unlikely]] return ErrorCode::EndOfFile;
            const u32 blk_hdr = load_le32(src.data() + pos);
            pos += 4u;
            if (blk_hdr == 0u) break; // EndMark

            const bool is_uncompressed = (blk_hdr & 0x80000000u) != 0u;
            const usize blk_size = as<usize>(blk_hdr & 0x7FFFFFFFu);
            if (blk_size > max_blk) [[unlikely]] return ErrorCode::InvalidData;
            if (src.size() - pos < blk_size) [[unlikely]] return ErrorCode::EndOfFile;

            const ArrayRef<u8> blk_data = src.slice(pos, blk_size);
            pos += blk_size;

            if (block_checksum) {
                if (src.size() - pos < 4u) [[unlikely]] return ErrorCode::EndOfFile;
                const u32 exp_bcrc = load_le32(src.data() + pos);
                pos += 4u;
                if (xxhash32(blk_data, 0u) != exp_bcrc) [[unlikely]] {
                    return ErrorCode::InvalidData;
                }
            }

            if (is_uncompressed) {
                if (opts.max_output_bytes > 0u &&
                    (blk_size > opts.max_output_bytes || out.size() > opts.max_output_bytes - blk_size)) [[unlikely]] {
                    return ErrorCode::OutOfRange;
                }
                out.append(blk_data);
            } else {
                const usize blk_out_before = out.size();
                const usize block_cap = (opts.max_output_bytes > 0u)
                    ? keel::min<usize>(opts.max_output_bytes, blk_out_before + max_blk)
                    : (blk_out_before + max_blk);
                const usize dict_base = block_indep ? blk_out_before : frame_out_start;
                const ErrorCode ec = lz4_decompress_block_into(blk_data, out, block_cap, dict_base);
                if (ec != ErrorCode::Ok) [[unlikely]] return ec;
            }
        }

        const usize frame_bytes = out.size() - frame_out_start;
        if (has_content_size && as<u64>(frame_bytes) != expected_content_size) [[unlikely]] {
            return ErrorCode::InvalidData;
        }
        if (content_checksum) {
            if (src.size() - pos < 4u) [[unlikely]] return ErrorCode::EndOfFile;
            const u32 exp_ccrc = load_le32(src.data() + pos);
            pos += 4u;
            if (xxhash32(out.as_ref().slice(frame_out_start), 0u) != exp_ccrc) [[unlikely]] {
                return ErrorCode::InvalidData;
            }
        }
    }

    if (!decoded_any_frame) {
        return out;
    }
    return out;
}

} // namespace keel::compress
