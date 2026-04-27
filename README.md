# Behringer Wing Compact — Firmware Exploration

Hardware reverse-engineering and firmware extraction of the Behringer Wing Compact
digital mixer.

## Accessing Firmware Download Mode

Pressing the tiny button between the USB-B and first network port and then
booting starts the CPU in USB SDP (Serial Download Protocol) download mode.

USB-Device Description:
```
SE Blank RIGEL:

  Location ID:    0x02110000
  Connection Type: Removable
  Manufacturer:   Freescale SemiConductor Inc
  Serial Number:  Not Provided
  Link Speed:     480 Mb/s
  USB Vendor ID:  0x15a2
  USB Product ID: 0x0061
  USB Product Version: 0x0001
```

UUU detection:
```
Path   Chip   Pro    Vid      Pid      BcdVersion   Serial_no
====================================================================
2:0    MX6D   SDP:   0x15A2   0x0061   0x0001
```

Note: UUU labels PID 0x0061 as "MX6D" but this PID covers both
DualLite and Solo variants. Physical chip marking confirms Solo.

## Hardware Identification

### Main SoC

| Field | Value |
|-------|-------|
| **Chip** | NXP i.MX6 Solo |
| **Part Number** | MCIMX6S8DVM10AC |
| **Cores** | 1× Cortex-A9 |
| **Max Freq** | 800 MHz |
| **DDR Bus** | 32-bit (single MMDC channel) |
| **Package** | 21×21mm BGA |

### RAM

| Field | Value |
|-------|-------|
| **Chips** | 2× Micron D9PSK (MT41K256M16) |
| **Type** | DDR3L |
| **Config** | 2×256Mx16 = 32-bit bus, 1 GB total |
| **Speed** | 800 MHz |

### eMMC Storage

| Field | Value |
|-------|-------|
| **Chip** | Toshiba THGBMTG5D1L8AIL |
| **Capacity** | 4 GB (3.7 GiB usable) |
| **Interface** | MMC v5.0, connected to USDHC3 |
| **Bus** | Currently running 4-bit (8-bit capable) |
| **Boot partitions** | 2× 2 MiB (both empty) |
| **RPMB** | 512 KiB |

### eMMC Partition Layout

```
/dev/disk4 (4.0 GB):
  #   TYPE            NAME        SIZE
  0   FDisk (MBR)                 4.0 GB
  1   Windows_FAT_32  WING_OS     804 MB    (starts at sector 2048)
  2   Windows_FAT_32  WING_DATA   2.1 GB
                      (free)      1.0 GB
```

#### WING_OS Partition Contents
- `wing-compact-release-3.1-20251107.wingfw` — 37 MB firmware update file

#### WING_DATA Partition Contents
- User snapshots/presets (e.g., `JUGO BAND.snap`)

## Boot Configuration

### eFuse Readout

```
Fuse bank 0, word 4: 0x00420702
Fuse bank 0, word 5: 0x08000030  (BOOT_CFG = SRC_SBMR1)
Fuse bank 0, word 6: 0x00000010  (BT_FUSE_SEL = 1)
```

### Boot Fuse Decoding

| Field | Value | Meaning |
|-------|-------|---------|
| `BOOT_MODE` | `10` (from SRC_SBMR2) | Internal boot |
| `BT_FUSE_SEL` | `1` | Boot config from fuses (not pins) |
| `BOOT_CFG1[7:4]` | `0011` | Serial ROM (I2C/SPI) |
| `BOOT_CFG1[3:0]` | `0000` | **ECSPI-1, SS0** |
| `BOOT_CFG4` | `0x08` | Additional boot config |
| **Boot device** | **SPI NOR flash on ECSPI-1** | Pads: EIM_D16 (MOSI), EIM_D17 (MISO), EIM_D18 (SCLK) |

> **Correction**: BOOT_CFG1=0x30 indicates **SPI NOR boot via ECSPI**, not
> I2C as previously assumed. The NXP i.MX6 reference manual confirms that
> bits [3:2]=`00` in the serial ROM boot group selects ECSPI (not I2C).

### SRC_SBMR2 Status

| Field | Value | Meaning |
|-------|-------|---------|
| `SEC_CONFIG[0]` | `1` | Security configuration bit set |
| `DIR_BT_DIS` | `1` | Serial download via USB disabled in fuses |

### OTP Fuse Security Status

| Bank | Content | Status |
|------|---------|--------|
| Bank 2 | Crypto/key material | **Access-protected (read-locked)** — may contain encryption keys |
| Bank 3 | SRK hash (HAB) | All zeros — HAB secure boot **not configured** |
| Bank 4 | GP fuses | All zeros |

### Boot Chain Analysis

The i.MX6 ROM is configured to boot from a **SPI NOR flash on ECSPI-1**.
However, `sf probe` from our custom U-Boot returns **JEDEC ID 00,00,00**
despite:

- Manual IOMUX configuration of EIM_D16/D17/D18 to ALT1 (ECSPI1 function)
- Testing both GPIO chip-select (EIM_D19) and hardware CS (EIM_EB2)
- Confirming ECSPI1 CONREG shows the controller is enabled and active

This indicates the Wing PCB routes the SPI flash signals differently than
the Nitrogen6x/SabreSD reference designs. The SPI flash chip is physically
present (the board boots from it normally) but the IOMUX pin assignments
on the Wing board do not match the standard EIM_D16–D19 mapping.

### Likely Boot Chain

```
i.MX6 ROM → SPI NOR flash (ECSPI-1) → eMMC user partition → Linux
```

The SPI NOR flash contains the first-stage bootloader that:
1. Initializes DDR (via DCD)
2. Loads the main bootloader or kernel from the eMMC WING_OS partition
3. The `.wingfw` file may be used for firmware updates only

## Firmware File Analysis (.wingfw)

| Field | Value |
|-------|-------|
| **File** | `wing-compact-release-3.1-20251107.wingfw` |
| **Size** | 38,744,576 bytes (36.9 MB) |
| **Entropy** | 7.37 bits/byte (near-maximum) |
| **Format** | **Encrypted** — no recognizable headers |

### Entropy Profile

- `0x000000–0x230000`: High entropy (~8.0) — encrypted
- `0x230000–0x460000`: Medium entropy (~6.1) — compressed or obfuscated code
- `0x460000–0x540000`: High entropy (~7.0) — encrypted/compressed
- `0x540000–0x600000`: Lower entropy (~6.4) — contains embedded cleartext

### Embedded Metadata

At offset `0x550470`, cleartext JSON mixer preset/snapshot data:
```json
{
  "type": "snapshot.4",
  "creator_fw": "3.0.6-193-g60c910ab-dirty:dev_unidyn4",
  "model": "wing-compact",
  "version": "...",
  "sn": "EMU...",
  ...
}
```

Key finding: `g60c910ab` is a **git commit hash**, confirming the firmware
is built from a version-controlled source. The `dev_unidyn4` suffix suggests
a development branch name.

### Signatures Found (likely false positives in encrypted data)

| Signature | Offset | Assessment |
|-----------|--------|------------|
| GZIP (1f 8b) | 0x00face | False positive (compression method=20, not 8) |
| PK (ZIP) | 0x023b65 | False positive (invalid ZIP structure) |
| "wing" text | 0x550b83 | Real — embedded snapshot JSON |

### Conclusion

The `.wingfw` file is an **encrypted firmware update package**. It does not
contain a directly extractable bootloader. Decryption keys would be needed
to extract the kernel, rootfs, and application binaries.

## USDHC Controller Mapping

From the i.MX6 Solo datasheet (IMX6SDLCEC):

| Controller | U-Boot index | Status | Notes |
|------------|-------------|--------|-------|
| USDHC1 | — | Not enabled in DT | — |
| USDHC2 | mmc dev 1 | Voltage select error | WiFi module on nitrogen6x; unknown on Wing |
| USDHC3 | mmc dev 2 | **eMMC found** | Toshiba 4GB, MMC v5.0 |
| USDHC4 | mmc dev 3 | Voltage select error | May have different pad routing on Wing |

Per datasheet, **USDHC3 and USDHC4** are designed for eMMC (hardware reset
support, dedicated 8-bit data lines).

## SPI Flash

SPI flash probe on ECSPI-1 (EIM_D16/D17/D18 pads) returns JEDEC ID
`00, 00, 00` — **no response on the standard reference-board pins**.

The boot fuses confirm SPI NOR boot on ECSPI-1, so the flash chip is
present but likely connected to different IOMUX-capable pads on the Wing
PCB. The i.MX6 ECSPI1 signals can be routed to multiple pad groups;
the Wing uses a non-standard mapping that requires physical board
inspection to determine.

## U-Boot Tools

See [u-boot/README.md](u-boot/README.md) for custom U-Boot builds that
enable:
- **USB Mass Storage**: Expose the eMMC as a USB drive for dumping
- **USB Serial Console**: Interactive U-Boot shell over USB

## Wingfw Decoder

The reverse-engineered `.wingfw` package notes now live in
[`docs/wingfw-reverse-engineering.md`](docs/wingfw-reverse-engineering.md).

This repo also includes an experimental Bun-based decoder at
[`tools/wingfw-decode.ts`](tools/wingfw-decode.ts). It mirrors the current
bootloader analysis and can:

- scan the whole package for high-entropy encrypted regions and extract them
- decrypt the `.wingfw` outer header with the now-verified `9af5...8a2f`
  seed block and parse its `~`-delimited manifest
- extract manifest fields including `APPPACK`, `APPADDR`, `APPKEY`,
  `RSRCPACK`, `RSRCSIZE`, `ENTRYPOINT`, and `APPSIZE`
- run manual payload decryption for the still-partial MD5-derived inner stages

Run it with:

```bash
bun run wingfw:decode -- --input /path/to/firmware.wingfw --output-dir ./decode-out
```

## Contributors
- Niklas Arnitz
-
