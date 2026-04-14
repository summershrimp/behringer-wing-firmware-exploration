# Wingfw Reverse Engineering Notes

This document captures the `.wingfw` update-package findings recovered from the
Behringer Wing Compact SPI flash image and the custom NGC bootloader stored in
that flash.

## Sample Artifacts

- Authoritative SPI flash dump: `wing-spi-w25q64jv-redump.bin`
- Earlier SPI flash dump with confirmed corruption in the helper region:
  `wing-spi-w25q64jv-recovered.bin`
- Firmware package: `wing-compact-release-3.1-20251107.wingfw`

## Bootloader Layout

The recovered 8 MiB Winbond W25Q64JV image contains a valid i.MX6 IVT header at
file offset `0x400`, which maps to linked address `0x2f00342c`.

- IVT file offset: `0x400`
- Entry point: `0x2f008000`
- `.wingfw` selector / outer-header loader: `0x2f009ee4`
- Main `.wingfw` unpacker: `0x2f00afb0`
- Context/key builder: `0x2f010b64` / `0x2f010b68`
- Rolling decrypt helper: `0x2f010c14` / `0x2f010c18`
- MD5 init: `0x2f010d94`
- MD5 update/final helpers: `0x2f01179c`, `0x2f011824`, `0x2f0118a0`
- LZ4-style payload unpacker: `0x2f013900`
- Metadata strings: `0x2f01e074`

## Embedded Metadata Keys

The bootloader contains explicit strings for the package parser:

- `.wingfw`
- `VERSION`
- `CDATE`
- `DEVTYPE`
- `APPPACK`
- `APPADDR`
- `APPKEY`
- `RSRCPACK`
- `RSRCSIZE`
- `ENTRYPOINT`
- `APPSIZE`

It also contains the hard-coded model string `wing-compact` and the error
message `ERROR: Firmware file does not support model '%s'`.

## Loader Flow

There are two related paths in the bootloader:

- `0x2f009ee4` selects a `.wingfw` file for the current model, reads its first
  `0x400` bytes, decrypts that outer header, and parses the package manifest.
- `0x2f00afb0` consumes the already selected package buffer, parses the
  decrypted manifest, derives the inner keys, decrypts the payloads, expands
  them, and verifies the split `APPKEY` digest.

The combined `.wingfw` path performs these stages:

1. Read the first `0x400` bytes of the `.wingfw` file.
2. Build an outer crypto context using `0xFEEDCAFE` and the 16-byte block
   `9a f5 b1 17 45 8e 2f d3 cc 92 f9 ce 22 b0 8a 2f`.
3. Apply the rolling block transform to those `0x400` bytes.
4. Parse a `~`-delimited ASCII manifest beginning with a record such as
   `:NGC72E2~...`.
5. Extract fields including `APPADDR`, `APPKEY`, `APPPACK`, `APPSIZE`,
   `CDATE`, `DEVTYPE`, `ENTRYPOINT`, `RSRCPACK`, `RSRCSIZE`, and `VERSION`.
6. Validate the package model against the bootloader's internal
   `wing-compact` string.
7. Run an MD5-based derivation step for the application package.
8. Decrypt the application payload.
9. Pass the decrypted application payload through the LZ4-style
   decompressor/copy engine at `0x2f013900`.
10. Run a second MD5-based derivation step for the resource package.
11. Decrypt the resource payload.
12. Expand the resource payload with the same LZ4-style unpacker.
13. Verify the two 16-byte halves of `APPKEY` against the MD5 of the expanded
   application and expanded resource regions.

The recovered outer manifest for the current sample is:

```text
:NGC72E2~APPADDR=10004000~APPKEY=74:4E:34:94:39:2E:23:07:0B:82:C2:EE:CE:B9:6E:3B:7B:C4:C3:95:A7:91:9F:34:51:98:8B:30:13:76:18:0B~APPPACK=1229312~APPSIZE=2611240~CDATE=2025-11-19_09:16:52~DEVTYPE=compact,wing-compact~ENTRYPOINT=10008000~RSRCPACK=37514240~RSRCSIZE=54665728~VERSION=3.1-0-g9f314617:release
```

## Outer Seed Block

The verified `.wingfw` outer-header loader at `0x2f009ee4` seeds the outer
stage with:

- mode: `2`
- seed word: `0xFEEDCAFE`
- seed block address: `0x2f01e0f0` (same bytes also appear at `0x2f01e2b4`)

Those 16 bytes decode to the literal block:

```text
9a f5 b1 17 45 8e 2f d3 cc 92 f9 ce 22 b0 8a 2f
```

The earlier `APPSIZE`-adjacent block at `0x2f01e288` belongs to a different
unpack path and should not be used for `.wingfw` file-header decryption. That
earlier interpretation came from the older corrupted SPI dump and is now known
to be wrong for the update-package loader.

## Context Builder Helper

The helper at `0x2f010b64` / `0x2f010b68` constructs a small mutable context
object:

1. Store the mode word.
2. Read four 32-bit little-endian words from the 16-byte seed block.
3. Copy those four words into a second 4-word shadow area.
4. Store the extra 32-bit seed word.

The actual per-block mutation happens in the tail helper at `0x2f010bcc`, which
adds the seed-word bytes onto the live key words after each decrypted block.

## Rolling Decrypt Helper

The transform at `0x2f010c14` / `0x2f010c18` is not a plain one-shot XXTEA over
the whole package. The fresh SPI redump resolves the earlier ambiguity and shows
that the true contract is:

- it operates on 32-bit word pairs (`64` bits at a time)
- it writes both words back; the earlier one-word writeback theory was caused by
  corrupted bytes in the old dump
- it supports odd trailing word counts by treating the missing partner as `0`
- it evolves the crypto context between blocks by calling the context-tail
  helper after each block
- it uses the constants `0x37b99e79`, `0xc8466187`, and the terminal sum `0x2a`

The structure is XTEA-like, but with a rolling context and a non-standard sum
schedule. In pseudocode, each block does:

```text
sum = rounds * 0x37b99e79 + 0x2a
while sum != 0x2a after the round body:
    v1 -= F(v0) ^ (sum + key[(sum >> 11) & 3])
    sum += 0xc8466187
    v0 -= F(v1) ^ (sum + key[sum & 3])
store v0, v1
mutate key words with the 4 bytes of seedword
```

## MD5-Derived Inner Keys

The MD5 init routine at `0x2f010d94` uses the standard IV values:

- `0x67452301`
- `0xefcdab89`
- `0x98badcfe`
- `0x10325476`

The inner application and resource decrypt stages hash metadata-derived strings,
finalize to a 16-byte digest, and feed that digest back into the same context
builder used by the outer stage.

The first KDF string is formatted with:

```text
%s-%s-%s-%08x
```

The final `%08x` argument is `APPSIZE`. After the application MD5 is prepared,
the bootloader removes the trailing `-%08x` suffix and hashes the shorter
`%s-%s-%s` string for the resource stage.

The bootloader then builds the payload contexts as:

- application: mode `9`, seed `md5(%s-%s-%s-%08x)`, seed word `RSRCSIZE`
- resource: mode `2`, seed `md5(%s-%s-%s)`, seed word `APPSIZE`

The exact runtime source of the three `%s` arguments is still being traced, but
the string shape and numeric argument handling are now settled.

The decoder therefore needs to support two states:

- fully automatic outer-header decrypt and manifest parse
- still-partial inner payload derivation until the three runtime `%s` sources
  are wired in exactly

## Metadata Format Observations

Static analysis of the parser helpers shows:

- `0x7e` (`~`) is the primary field delimiter
- records begin after a 9-byte `:NGCxxxx~` style prefix
- manifest entries are `KEY=VALUE` records
- decimal numbers are parsed with a normal `value = value * 10 + digit` loop
- hex byte lists such as `APPKEY` are parsed as colon-delimited 8-bit values
- the model gate is explicit and rejects packages whose metadata does not match
  `wing-compact`

`APPKEY` is a 32-byte colon-delimited list. The bootloader uses the first 16
bytes as the expected MD5 of the expanded application payload and the second 16
bytes as the expected MD5 of the expanded resource payload.

## Entropy-Based Region Split

Running a binwalk-style entropy scan over `wing-compact-release-3.1-20251107.wingfw`
shows that the whole 36.9 MiB file is not uniformly encrypted.

The strongest high-entropy spans in the current sample are:

- `0x000000-0x230000` — sustained near-maximum entropy, likely the primary
  encrypted application/update block
- `0x490000-0x540000` — a second high-entropy block, likely a later encrypted
  resource block

The region between them drops into the low-6-bit entropy range, which is more
consistent with compressed or packed data than with a uniformly encrypted blob.
The Bun decoder now extracts these likely encrypted spans first and writes them
out as standalone files for faster iteration.

## Bun Decoder

An experimental Bun-based decoder is included at:

- `tools/wingfw-decode.ts`

Run it with:

```bash
bun run wingfw:decode -- --input /path/to/firmware.wingfw --output-dir ./decode-out
```

What it does today:

1. Performs a binwalk-style entropy scan across the full package.
2. Extracts the likely encrypted regions into standalone `.bin` files.
3. Stops there by default.
4. Only runs the slower outer-header candidate ranking when
   `--analyze-header` is supplied explicitly.
5. Still needs the exact runtime `%s` sources wired in for fully automatic inner
   payload decryption.

The old dump-driven uncertainty around the rolling helper is now resolved. The
remaining work is not the block transform itself, but finishing the exact MD5
string source mapping and updating the Bun decoder accordingly.
