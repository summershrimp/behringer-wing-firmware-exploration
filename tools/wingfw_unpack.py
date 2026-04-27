#!/usr/bin/env python3
import argparse
import hashlib
import json
import struct
from pathlib import Path


HEADER_KEY = bytes.fromhex("9a f5 b1 17 45 8e 2f d3 cc 92 f9 ce 22 b0 8a 2f")
HEADER_ROUNDS = 2
HEADER_STEP = 0xFEEDCAFE
HEADER_SIZE = 0x400
XTEA_DELTA = 0x37B99E79

KEY_PART0 = "MUSIC_Tribe_Brands_DE_GmbH"
KEY_PART1 = "Thomas_Zint"
KEY_PART2 = "NGC_PROJECT"


def u32(value):
    return value & 0xFFFFFFFF


def read_u32le(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def write_u32le(buf, off, value):
    struct.pack_into("<I", buf, off, u32(value))


class XteaVariant:
    def __init__(self, rounds, key, step):
        if len(key) != 16:
            raise ValueError("XTEA variant key must be 16 bytes")
        self.rounds = rounds
        self.key = [
            read_u32le(key, 0),
            read_u32le(key, 4),
            read_u32le(key, 8),
            read_u32le(key, 12),
        ]
        self.step = step

    def advance_key(self, blocks=1):
        self.key[0] = u32(self.key[0] + blocks * ((self.step >> 24) & 0xFF))
        self.key[1] = u32(self.key[1] + blocks * ((self.step >> 16) & 0xFF))
        self.key[2] = u32(self.key[2] + blocks * ((self.step >> 8) & 0xFF))
        self.key[3] = u32(self.key[3] + blocks * (self.step & 0xFF))

    def decrypt_words_inplace(self, buf, off, word_count):
        if word_count <= 0:
            return

        remain = word_count
        in_off = off
        out_off = off
        stop = u32(word_count - 2 - ((word_count - 1) & 0xFFFFFFFE))
        odd = word_count & 1

        while remain > stop:
            y = read_u32le(buf, in_off)
            z = read_u32le(buf, in_off + 4) if remain > 1 else 0
            in_off += 8 if remain > 1 else 4

            if self.rounds > 0:
                total = u32(XTEA_DELTA * self.rounds + 0x2A)
                while True:
                    z = u32(
                        z
                        - (
                            u32(((y >> 5) ^ u32(y << 4)) + y)
                            ^ u32(total + self.key[((total >> 11) & 3)])
                        )
                    )
                    total = u32(total - XTEA_DELTA)
                    y = u32(
                        y
                        - (
                            u32(((z >> 5) ^ u32(z << 4)) + z)
                            ^ u32(total + self.key[total & 3])
                        )
                    )
                    if total == 0x2A:
                        break

            write_u32le(buf, out_off, y)
            out_off += 4
            if odd == remain:
                self.advance_key()
                break

            write_u32le(buf, out_off, z)
            out_off += 4
            remain -= 2
            self.advance_key()


def raw_lz4_decompress(src, output_size):
    out = bytearray(output_size)
    ip = 0
    op = 0

    while ip < len(src) and op < output_size:
        token = src[ip]
        ip += 1

        literal_len = token >> 4
        if literal_len == 15:
            while True:
                if ip >= len(src):
                    raise ValueError("LZ4 literal length overrun")
                add = src[ip]
                ip += 1
                literal_len += add
                if add != 255:
                    break

        if ip + literal_len > len(src) or op + literal_len > output_size:
            raise ValueError("LZ4 literal copy out of bounds")
        out[op : op + literal_len] = src[ip : ip + literal_len]
        ip += literal_len
        op += literal_len

        if op >= output_size:
            return bytes(out)

        if ip + 2 > len(src):
            raise ValueError("LZ4 missing match offset")
        match_offset = src[ip] | (src[ip + 1] << 8)
        ip += 2
        if match_offset == 0 or match_offset > op:
            raise ValueError(f"LZ4 bad match offset {match_offset} at input 0x{ip:x}")

        match_len = (token & 0x0F) + 4
        if (token & 0x0F) == 15:
            while True:
                if ip >= len(src):
                    raise ValueError("LZ4 match length overrun")
                add = src[ip]
                ip += 1
                match_len += add
                if add != 255:
                    break

        if op + match_len > output_size:
            raise ValueError("LZ4 match copy out of bounds")
        ref = op - match_offset
        for _ in range(match_len):
            out[op] = out[ref]
            op += 1
            ref += 1

    if op != output_size:
        raise ValueError(f"LZ4 output short: got {op}, expected {output_size}")
    return bytes(out)


def parse_ngc_header(header):
    header = header.split(b"\x00", 1)[0]
    if not header.startswith(b":NGC"):
        raise ValueError("decrypted header does not start with :NGC")

    text = header.decode("ascii", errors="strict")
    body = text.split("~", 1)[1] if "~" in text else ""
    fields = {}
    for item in body.split("~"):
        if not item or "=" not in item:
            continue
        key, value = item.split("=", 1)
        fields[key] = value
    return fields, text


def parse_appkey(value):
    parts = [p for p in value.split(":") if p]
    data = bytes(int(p, 16) for p in parts)
    if len(data) != 32:
        raise ValueError(f"APPKEY has {len(data)} bytes, expected 32")
    return data


def parse_u32_hex(value):
    return int(value, 16)


def align512(value):
    return (value + 511) & 0xFFFFFE00


def align_for_rsrc_packed(value):
    return (value + 1535) & 0xFFFFFE00


def md5(data):
    return hashlib.md5(data).digest()


def unpack_firmware(input_path, output_dir):
    blob = bytearray(input_path.read_bytes())
    if len(blob) < HEADER_SIZE:
        raise ValueError("firmware file is smaller than the encrypted header")

    XteaVariant(HEADER_ROUNDS, HEADER_KEY, HEADER_STEP).decrypt_words_inplace(
        blob, 0, HEADER_SIZE // 4
    )
    meta, header_text = parse_ngc_header(bytes(blob[:HEADER_SIZE]))

    app_size = int(meta["APPSIZE"])
    app_pack = int(meta["APPPACK"])
    app_addr = parse_u32_hex(meta["APPADDR"])
    rsrc_size = int(meta["RSRCSIZE"])
    rsrc_pack = int(meta["RSRCPACK"])
    entrypoint = parse_u32_hex(meta["ENTRYPOINT"])
    appkey = parse_appkey(meta["APPKEY"])

    key_string = f"{KEY_PART0}-{KEY_PART1}-{KEY_PART2}-{app_size:08X}"
    app_decrypt_key = md5(key_string.encode("ascii"))
    rsrc_key_string = key_string[:-9]
    rsrc_decrypt_key = md5(rsrc_key_string.encode("ascii"))

    app_off = HEADER_SIZE
    app_end = app_off + app_pack
    if app_end > len(blob):
        raise ValueError("APP packed data extends past end of file")

    app_lz4_dec = bytearray(blob[app_off:app_end])
    XteaVariant(9, app_decrypt_key, rsrc_size).decrypt_words_inplace(
        app_lz4_dec, 0, app_pack // 4
    )
    app_bin = raw_lz4_decompress(app_lz4_dec, app_size)

    app_md5 = md5(app_bin)
    if app_md5 != appkey[:16]:
        raise ValueError(
            f"APP MD5 mismatch: got {app_md5.hex()}, expected {appkey[:16].hex()}"
        )

    rsrc_off = align_for_rsrc_packed(app_pack)
    rsrc_end = rsrc_off + rsrc_pack
    if rsrc_end > len(blob):
        raise ValueError("RSRC packed data extends past end of file")

    rsrc_lz4_dec = bytearray(blob[rsrc_off:rsrc_end])
    rsrc_encrypted_len = min(rsrc_pack, 0x100000)
    XteaVariant(2, rsrc_decrypt_key, app_size).decrypt_words_inplace(
        rsrc_lz4_dec, 0, rsrc_encrypted_len // 4
    )
    rsrc_bin = raw_lz4_decompress(rsrc_lz4_dec, rsrc_size)

    rsrc_md5 = md5(rsrc_bin)
    if rsrc_md5 != appkey[16:]:
        raise ValueError(
            f"RSRC MD5 mismatch: got {rsrc_md5.hex()}, expected {appkey[16:].hex()}"
        )

    rsrc_addr = app_addr + align512(app_size)
    output_dir.mkdir(parents=True, exist_ok=True)

    app_path = output_dir / f"app_0x{app_addr:08X}.bin"
    rsrc_path = output_dir / f"rsrc_0x{rsrc_addr:08X}.bin"
    app_lz4_path = output_dir / "app.lz4.dec"
    rsrc_lz4_path = output_dir / "rsrc.lz4.dec"
    meta_path = output_dir / "metadata.json"
    header_path = output_dir / "header.ngc.txt"

    app_path.write_bytes(app_bin)
    rsrc_path.write_bytes(rsrc_bin)
    app_lz4_path.write_bytes(app_lz4_dec)
    rsrc_lz4_path.write_bytes(rsrc_lz4_dec)
    header_path.write_text(header_text, encoding="ascii")

    summary = {
        "input": str(input_path),
        "version": meta.get("VERSION"),
        "cdate": meta.get("CDATE"),
        "devtype": meta.get("DEVTYPE"),
        "app_addr": f"0x{app_addr:08X}",
        "app_pack": app_pack,
        "app_size": app_size,
        "app_md5": app_md5.hex(),
        "app_decrypt_key": app_decrypt_key.hex(),
        "app_output": str(app_path),
        "app_lz4_dec_output": str(app_lz4_path),
        "rsrc_addr": f"0x{rsrc_addr:08X}",
        "rsrc_pack": rsrc_pack,
        "rsrc_size": rsrc_size,
        "rsrc_md5": rsrc_md5.hex(),
        "rsrc_decrypt_key": rsrc_decrypt_key.hex(),
        "rsrc_output": str(rsrc_path),
        "rsrc_lz4_dec_output": str(rsrc_lz4_path),
        "entrypoint": f"0x{entrypoint:08X}",
        "key_string": key_string,
        "rsrc_key_string": rsrc_key_string,
        "metadata": meta,
    }
    meta_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt and unpack Behringer WING .wingfw firmware."
    )
    parser.add_argument("firmware", type=Path, help="input .wingfw file")
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        help="output directory, default: <firmware stem>_unpacked",
    )
    args = parser.parse_args()

    input_path = args.firmware.resolve()
    output_dir = args.output_dir
    if output_dir is None:
        output_dir = input_path.with_name(f"{input_path.stem}_unpacked")
    else:
        output_dir = output_dir.resolve()

    summary = unpack_firmware(input_path, output_dir)
    print(f"VERSION:    {summary['version']}")
    print(f"CDATE:      {summary['cdate']}")
    print(f"ENTRYPOINT: {summary['entrypoint']}")
    print(f"APP:        {summary['app_output']} ({summary['app_size']} bytes)")
    print(f"APP MD5:    {summary['app_md5']}")
    print(f"RSRC:       {summary['rsrc_output']} ({summary['rsrc_size']} bytes)")
    print(f"RSRC MD5:   {summary['rsrc_md5']}")
    print(f"Metadata:   {output_dir / 'metadata.json'}")


if __name__ == "__main__":
    main()
