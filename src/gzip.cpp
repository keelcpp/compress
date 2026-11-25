#include "keel/compress/gzip.h"

#include "keel/compress/checksum.h"

namespace keel::compress {

namespace {

constexpr u8 kGzipId1 = 0x1Fu;
constexpr u8 kGzipId2 = 0x8Bu;
constexpr u8 kGzipMethodDeflate = 8u;

constexpr u8 kFlgFtext = 1u << 0u;
constexpr u8 kFlgFhcrc = 1u << 1u;
constexpr u8 kFlgFextra = 1u << 2u;
constexpr u8 kFlgFname = 1u << 3u;
constexpr u8 kFlgFcomment = 1u << 4u;
constexpr u8 kFlgReservedMask = 0xE0u;

constexpr u16 load_le16(const u8* p) noexcept {
    return as<u16>(as<u16>(p[0]) | (as<u16>(p[1]) << 8u));
}

constexpr u32 load_le32(const u8* p) noexcept {
    return as<u32>(p[0]) | (as<u32>(p[1]) << 8u) | (as<u32>(p[2]) << 16u) | (as<u32>(p[3]) << 24u);
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

Result<usize> parse_gzip_header_impl(ArrayRef<u8> src, GzipHeader* hdr_out, Allocator* alloc) {
    if (src.size() < 10u) [[unlikely]] {
        return ErrorCode::EndOfFile;
    }
    if (src[0] != kGzipId1 || src[1] != kGzipId2) [[unlikely]] {
        return ErrorCode::InvalidData;
    }
    if (src[2] != kGzipMethodDeflate) [[unlikely]] {
        return ErrorCode::NotSupported;
    }
    const u8 flg = src[3];
    if ((flg & kFlgReservedMask) != 0u) [[unlikely]] {
        return ErrorCode::InvalidData;
    }

    if (hdr_out) {
        hdr_out->mtime = load_le32(src.data() + 4u);
        hdr_out->xfl = src[8];
        hdr_out->os = src[9];
        hdr_out->is_text = (flg & kFlgFtext) != 0u;
    }

    usize pos = 10u;

    if ((flg & kFlgFextra) != 0u) {
        if (src.size() - pos < 2u) [[unlikely]] return ErrorCode::EndOfFile;
        const usize xlen = as<usize>(load_le16(src.data() + pos));
        pos += 2u;
        if (src.size() - pos < xlen) [[unlikely]] return ErrorCode::EndOfFile;
        if (hdr_out && xlen > 0u) {
            hdr_out->extra = Array<u8>(alloc);
            hdr_out->extra.append(src.slice(pos, xlen));
        }
        pos += xlen;
    }

    if ((flg & kFlgFname) != 0u) {
        const usize start = pos;
        while (pos < src.size() && src[pos] != 0u) ++pos;
        if (pos >= src.size()) [[unlikely]] return ErrorCode::EndOfFile;
        if (hdr_out) {
            hdr_out->filename = String::from(
                StringRef(reinterpret_cast<const char*>(src.data() + start), pos - start), alloc);
        }
        ++pos; // NUL terminator
    }

    if ((flg & kFlgFcomment) != 0u) {
        const usize start = pos;
        while (pos < src.size() && src[pos] != 0u) ++pos;
        if (pos >= src.size()) [[unlikely]] return ErrorCode::EndOfFile;
        if (hdr_out) {
            hdr_out->comment = String::from(
                StringRef(reinterpret_cast<const char*>(src.data() + start), pos - start), alloc);
        }
        ++pos; // NUL terminator
    }

    if ((flg & kFlgFhcrc) != 0u) {
        if (src.size() - pos < 2u) [[unlikely]] return ErrorCode::EndOfFile;
        const u16 expected_hcrc = load_le16(src.data() + pos);
        const u16 actual_hcrc = as<u16>(crc32(src.slice(0u, pos)) & 0xFFFFu);
        if (expected_hcrc != actual_hcrc) [[unlikely]] {
            return ErrorCode::InvalidData;
        }
        pos += 2u;
    }

    if (hdr_out) {
        hdr_out->header_bytes = pos;
    }
    return pos;
}

} // namespace

Result<GzipHeader> gzip_peek_header(ArrayRef<u8> src, Allocator* alloc) {
    Allocator* a = alloc ? alloc : default_allocator();
    GzipHeader hdr{};
    hdr.filename = String(a);
    hdr.comment = String(a);
    hdr.extra = Array<u8>(a);
    KEEL_TRY(parse_gzip_header_impl(src, &hdr, a));
    return hdr;
}

Array<u8> gzip_compress(ArrayRef<u8> src, const GzipOptions& opts) {
    Allocator* alloc = opts.allocator ? opts.allocator : default_allocator();
    Array<u8> out(alloc);
    out.reserve((src.size() / 2u) + 64u);

    u8 flg = 0u;
    if (!opts.filename.empty()) flg = as<u8>(flg | kFlgFname);
    if (!opts.comment.empty()) flg = as<u8>(flg | kFlgFcomment);
    if (opts.write_header_crc) flg = as<u8>(flg | kFlgFhcrc);

    out.push_back(kGzipId1);
    out.push_back(kGzipId2);
    out.push_back(kGzipMethodDeflate);
    out.push_back(flg);
    push_le32(out, opts.mtime);
    out.push_back((opts.level >= 9) ? 0x02u : ((opts.level <= 1) ? 0x04u : 0x00u));
    out.push_back(opts.os);

    if (!opts.filename.empty()) {
        for (usize i = 0u; i < opts.filename.size(); ++i) {
            const u8 c = as<u8>(opts.filename.data()[i]);
            if (c != 0u) out.push_back(c);
        }
        out.push_back(0u);
    }
    if (!opts.comment.empty()) {
        for (usize i = 0u; i < opts.comment.size(); ++i) {
            const u8 c = as<u8>(opts.comment.data()[i]);
            if (c != 0u) out.push_back(c);
        }
        out.push_back(0u);
    }
    if (opts.write_header_crc) {
        const u16 hcrc = as<u16>(crc32(out.as_ref()) & 0xFFFFu);
        push_le16(out, hcrc);
    }

    Array<u8> deflated = deflate_raw(src, opts.level, alloc);
    out.append(deflated.as_ref());

    push_le32(out, crc32(src));
    push_le32(out, as<u32>(as<u64>(src.size()) & 0xFFFFFFFFull));
    return out;
}

Result<Array<u8>> gzip_decompress(ArrayRef<u8> src, const InflateOptions& opts) {
    if (src.empty()) [[unlikely]] {
        return ErrorCode::EndOfFile;
    }

    Allocator* alloc = opts.allocator ? opts.allocator : default_allocator();
    Array<u8> out(alloc);
    if (opts.expected_size_hint > 0u) {
        constexpr usize kMaxReserve = 16ULL * 1024u * 1024u;
        usize cap = keel::min(opts.expected_size_hint, kMaxReserve);
        if (opts.max_output_bytes > 0u) cap = keel::min(cap, opts.max_output_bytes);
        out.reserve(cap);
    }

    usize pos = 0u;
    while (pos < src.size()) {
        const ArrayRef<u8> rem = src.slice(pos);
        KEEL_TRY_ASSIGN(const usize hdr_len, parse_gzip_header_impl(rem, nullptr, alloc));
        if (rem.size() < hdr_len + 8u) [[unlikely]] {
            return ErrorCode::EndOfFile;
        }

        InflateOptions member_opts = opts;
        member_opts.allocator = alloc;
        if (opts.max_output_bytes > 0u) {
            if (out.size() > opts.max_output_bytes) [[unlikely]] return ErrorCode::OutOfRange;
            member_opts.max_output_bytes = opts.max_output_bytes - out.size();
            if (member_opts.max_output_bytes == 0u) {
                // Allow zero-byte member only
                usize consumed = 0u;
                InflateOptions probe = member_opts;
                probe.max_output_bytes = 1u;
                KEEL_TRY_ASSIGN(Array<u8> part, inflate_raw_ex(rem.slice(hdr_len), consumed, probe));
                if (!part.empty()) return ErrorCode::OutOfRange;
                const usize tr_off = hdr_len + consumed;
                if (rem.size() - tr_off < 8u) return ErrorCode::EndOfFile;
                const u32 exp_crc = load_le32(rem.data() + tr_off);
                const u32 exp_isize = load_le32(rem.data() + tr_off + 4u);
                if (exp_crc != 0u || exp_isize != 0u) return ErrorCode::InvalidData;
                pos += tr_off + 8u;
                continue;
            }
        }

        usize consumed = 0u;
        KEEL_TRY_ASSIGN(Array<u8> part, inflate_raw_ex(rem.slice(hdr_len), consumed, member_opts));

        const usize tr_off = hdr_len + consumed;
        if (rem.size() - tr_off < 8u) [[unlikely]] {
            return ErrorCode::EndOfFile;
        }

        const u32 exp_crc = load_le32(rem.data() + tr_off);
        const u32 exp_isize = load_le32(rem.data() + tr_off + 4u);
        const u32 act_crc = crc32(part.as_ref());
        const u32 act_isize = as<u32>(as<u64>(part.size()) & 0xFFFFFFFFull);
        if (exp_crc != act_crc || exp_isize != act_isize) [[unlikely]] {
            return ErrorCode::InvalidData;
        }

        if (out.empty() && (pos + tr_off + 8u == src.size())) {
            return part;
        }
        out.append(part.as_ref());
        pos += tr_off + 8u;
    }

    return out;
}

} // namespace keel::compress
