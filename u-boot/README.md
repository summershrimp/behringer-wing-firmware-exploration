# Behringer Wing — U-Boot for Firmware Exploration

Custom U-Boot builds for the Behringer Wing digital mixer, enabling firmware
extraction via the i.MX6 USB SDP (Serial Download Protocol) boot mode.

## Hardware

| Component | Detail |
|-----------|--------|
| **SoC** | NXP i.MX6 Solo (MCIMX6S8DVM10AC) |
| **RAM** | 2× Micron MT41K256M16 (D9PSK) — 1 GB DDR3L, 32-bit bus |
| **eMMC** | Toshiba THGBMTG5D1L8AIL — 4 GB, MMC v5.0 |
| **USB PID** | `0x15A2:0x0061` (i.MX6 DualLite/Solo family) |
| **eMMC bus** | USDHC3 (mmc dev 2 in U-Boot) |

## Prebuilt Images

### `images/u-boot-ums.imx` — USB Mass Storage

Auto-exposes the 4 GB eMMC as a USB mass storage device. No serial console
needed — the eMMC appears as a USB drive on the host.

```bash
# 1. Put the Wing in USB boot mode (hold specific buttons at power-on)
# 2. Load U-Boot
sudo uuu u-boot/images/u-boot-ums.imx

# 3. The eMMC appears as a disk — find it
diskutil list

# 4. Dump the full eMMC image
sudo dd if=/dev/rdiskN of=wing-emmc.img bs=4m status=progress
sync
```

### `images/u-boot-console.imx` — USB Serial Console

Interactive U-Boot shell over USB CDC ACM serial. Use this to explore the
board, probe hardware, read memory, etc.

```bash
# 1. Load U-Boot
sudo uuu u-boot/images/u-boot-console.imx

# 2. Connect to the serial console
screen /dev/cu.usbmodem* 115200

# 3. Useful commands at the U-Boot prompt:
mmc list                    # List MMC controllers
mmc dev 2; mmc info         # Show eMMC info
mmc part                    # Show partition table
md.b 0x10000000 0x100       # Dump memory
sf probe                    # Probe SPI NOR flash
```

## Building from Source

Based on U-Boot v2024.01 with patches for the Behringer Wing hardware.

### Prerequisites

```bash
brew install arm-none-eabi-gcc make dtc
```

### Build

```bash
git clone --depth 1 -b v2024.01 https://source.denx.de/u-boot/u-boot.git
cd u-boot

# Apply the Wing hardware patch
git apply ../patches/behringer-wing-imx6s.patch

# Copy defconfigs
cp ../configs/mx6d_ums_defconfig configs/
cp ../configs/mx6d_usbconsole_defconfig configs/

# Build UMS variant
gmake CROSS_COMPILE=arm-none-eabi- mx6d_ums_defconfig
gmake CROSS_COMPILE=arm-none-eabi- -j$(sysctl -n hw.ncpu)
cp u-boot-dtb.imx ../images/u-boot-ums.imx

# Build console variant
gmake CROSS_COMPILE=arm-none-eabi- distclean
gmake CROSS_COMPILE=arm-none-eabi- mx6d_usbconsole_defconfig
gmake CROSS_COMPILE=arm-none-eabi- -j$(sysctl -n hw.ncpu)
cp u-boot-dtb.imx ../images/u-boot-console.imx
```

## Key Modifications (patch summary)

The patch modifies U-Boot v2024.01 to support the Wing's hardware:

1. **DDR config**: Uses `nitrogen6s1g.cfg` (i.MX6 Solo, 2×256Mx16, 800MHz, 32-bit bus, 1 GB)
2. **Board init stripped**: Removed nitrogen6x-specific I2C, PMIC, GPIO, video,
   and SPI setup that crashes on non-matching hardware
3. **`overwrite_console()` returns 0**: Allows USB ACM serial to be used as console
4. **USDHC3/4 configured for 8-bit eMMC**: Device tree modified with dedicated
   DAT4-7 data pins and hardware reset signals
5. **USB ACM gadget**: `CONFIG_USB_FUNCTION_ACM` enabled for serial console variant
6. **Default env**: `stdin=usbacm,serial`, `stdout=usbacm,serial`, `stderr=usbacm,serial`

## Notes

- The U-Boot images are **RAM-only** — nothing is written to the Wing's storage.
  Power cycle to return to normal operation.
- The eMMC is on **USDHC3** (U-Boot `mmc dev 2`), running at 4-bit bus width.
- Boot partitions (2× 2 MiB) may contain the original bootloader.
- `USDHC1` shows "voltage select" error — may need different pad config.
- Built and tested on macOS (Apple Silicon) with `arm-none-eabi-gcc 15.2.0`.
