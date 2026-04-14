#!/usr/bin/env bun

import { createHash } from "node:crypto"
import { mkdir, writeFile } from "node:fs/promises"
import { basename, join, resolve } from "node:path"

type ParsedArgs = {
  input?: string
  outputDir: string
  dumpCandidates: number
  transform?: string
  analyzeHeader: boolean
  decryptInner: boolean
  json: boolean
  decryptOffset?: number
  decryptLength?: number
  kdf?: string
  seedWord?: number
  mode?: number
  outputFile?: string
  seedBlockHex?: string
}

type UpdateMode = "none" | "seed-byte" | "mode-byte"
type RoundMode = "loader" | "xtea32"

type TransformConfig = {
  id: string
  description: string
  delta: number
  rounds: RoundMode
  updateMode: UpdateMode
}

type SeedConfig = {
  id: string
  description: string
  mode: number
  seedWord: number
  seedBlock: Uint8Array
}

type CipherContext = {
  mode: number
  seedWord: number
  seedBytes: [number, number, number, number]
  initialWords: [number, number, number, number]
  keyWords: [number, number, number, number]
}

type HeaderAnalysis = {
  printableRatio: number
  tokenHits: string[]
  metadata: Record<string, string>
  score: number
  text: string
}

type HeaderCandidate = {
  id: string
  seed: string
  transform: string
  analysis: HeaderAnalysis
  header: Uint8Array
}

type EntropyWindow = {
  offset: number
  end: number
  entropy: number
}

type EncryptedRegion = {
  offset: number
  end: number
  size: number
  maxEntropy: number
  averageEntropy: number
}

type InnerManifest = {
  appAddr: number
  appPack: number
  appSize: number
  appKey: Uint8Array
  entryPoint: number
  resourcePack: number
  resourceSize: number
}

type InnerDecryptResult = {
  transformId: string
  manifestSource: string
  app: {
    offset: number
    length: number
    mode: number
    seedWord: number
    kdf: string
    output: Uint8Array
    outputFile: string
  }
  resource: {
    offset: number
    length: number
    mode: number
    seedWord: number
    kdf: string
    output: Uint8Array
    outputFile: string
  }
  manifest: InnerManifest
}

type ProgressReporter = {
  update(current: number, detail?: string): void
  done(detail?: string): void
}

const OUTER_HEADER_SIZE = 0x400
const LOADER_SUM_END = 0x2a
const ENTROPY_WINDOW_SIZE = 0x10000
const ENTROPY_HIGH_THRESHOLD = 7.8
const ENTROPY_LOW_THRESHOLD = 6.9
const INNER_PACK_ALIGNMENT = 0x200
const DEFAULT_TRANSFORM_ID = "loader-delta-seed-update"
const INNER_KDF_PARTS = [
  "MUSIC_Tribe_Brands_DE_GmbH",
  "Thomas_Zint",
  "NGC_PROJECT",
]
const SETTLED_SAMPLE_MANIFESTS = [
  {
    fileName: "wing-compact-release-3.1-20251107.wingfw",
    size: 38_744_576,
    metadata: {
      APPADDR: "10004000",
      APPKEY:
        "74:4E:34:94:39:2E:23:07:0B:82:C2:EE:CE:B9:6E:3B:7B:C4:C3:95:A7:91:9F:34:51:98:8B:30:13:76:18:0B",
      APPPACK: "1229312",
      APPSIZE: "2611240",
      ENTRYPOINT: "10008000",
      RSRCPACK: "37514240",
      RSRCSIZE: "54665728",
    },
  },
]
const KNOWN_TOKENS = [
  ".wingfw",
  "VERSION",
  "CDATE",
  "DEVTYPE",
  "APPPACK",
  "APPADDR",
  "APPKEY",
  "RSRCPACK",
  "RSRCSIZE",
  "ENTRYPOINT",
  "APPSIZE",
  "wing-compact",
]

const TRANSFORMS: TransformConfig[] = [
  {
    id: "loader-delta-seed-update",
    description:
      "Recovered rolling pair decrypt using 0x37b99e79 and per-block seed-byte context updates",
    delta: 0x37b99e79,
    rounds: "loader",
    updateMode: "seed-byte",
  },
  {
    id: "loader-delta-static",
    description:
      "Recovered rolling pair decrypt using 0x37b99e79 with a static context",
    delta: 0x37b99e79,
    rounds: "loader",
    updateMode: "none",
  },
  {
    id: "loader-delta-mode-update",
    description:
      "Recovered rolling pair decrypt using 0x37b99e79 and mode-scaled context updates",
    delta: 0x37b99e79,
    rounds: "loader",
    updateMode: "mode-byte",
  },
  {
    id: "tea-delta-seed-update",
    description:
      "Recovered rolling pair decrypt using 0x9e3779b9 and per-block seed-byte context updates",
    delta: 0x9e3779b9,
    rounds: "loader",
    updateMode: "seed-byte",
  },
  {
    id: "tea-delta-static",
    description:
      "Recovered rolling pair decrypt using 0x9e3779b9 with a static context",
    delta: 0x9e3779b9,
    rounds: "loader",
    updateMode: "none",
  },
  {
    id: "xtea32-static",
    description: "Classic 32-round XTEA decrypt with a static context",
    delta: 0x9e3779b9,
    rounds: "xtea32",
    updateMode: "none",
  },
]

const OUTER_SEEDS: SeedConfig[] = [
  {
    id: "bootloader-e288",
    description:
      "Verified outer-header seed block used with 0xFEEDCAFE for .wingfw header decryption",
    mode: 2,
    seedWord: 0xfeedcafe,
    seedBlock: hexToBytes("9af5b117458e2fd3cc92f9ce22b08a2f"),
  },
]

function main(): Promise<void> {
  return run().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error)
    console.error(`wingfw-decode: ${message}`)
    process.exitCode = 1
  })
}

async function run(): Promise<void> {
  const args = parseArgs(process.argv.slice(2))

  if (!args.input) {
    printHelp()
    return
  }

  const inputPath = resolve(args.input)
  const input = await Bun.file(inputPath).bytes()
  const outputDir = resolve(args.outputDir)
  await mkdir(outputDir, { recursive: true })

  console.log(`Input: ${inputPath}`)
  console.log(`Output: ${outputDir}`)

  const entropyProgress = createProgressReporter(
    "Scanning entropy",
    Math.ceil(input.length / ENTROPY_WINDOW_SIZE),
  )
  const entropy = scanEntropy(input, ENTROPY_WINDOW_SIZE, entropyProgress)
  entropyProgress.done()

  const encryptedRegions = findEncryptedRegions(entropy)
  console.log(`Identified ${encryptedRegions.length} likely encrypted region(s)`)
  await writeEncryptedRegionArtifacts(outputDir, input, entropy, encryptedRegions)

  const summary: Record<string, unknown> = {
    input: inputPath,
    size: input.length,
    likelyEncryptedRegions: encryptedRegions.map((region) => ({
      offset: toHex(region.offset),
      end: toHex(region.end),
      size: region.size,
      maxEntropy: Number(region.maxEntropy.toFixed(6)),
      averageEntropy: Number(region.averageEntropy.toFixed(6)),
    })),
  }

  let candidates: HeaderCandidate[] = []
  let best: HeaderCandidate | undefined

  if (args.analyzeHeader || args.decryptInner) {
    const headerTransform = args.analyzeHeader ? args.transform : resolveInnerTransform(args.transform).id
    const candidateTotal = OUTER_SEEDS.length * pickTransforms(headerTransform).length
    const headerProgress = createProgressReporter(
      args.analyzeHeader ? "Ranking header candidates" : "Decrypting outer header",
      candidateTotal,
    )
    candidates = decodeOuterHeader(input, headerTransform, headerProgress)
    headerProgress.done()
    best = candidates[0]
    if (!best) {
      throw new Error("failed to decode the outer header")
    }

    summary.bestCandidate = summarizeCandidate(best)
    summary.candidateCount = candidates.length

    if (args.analyzeHeader) {
      await writeOuterArtifacts(outputDir, best, candidates, args.dumpCandidates)
    }
  }

  if (args.decryptInner) {
    if (!best) {
      throw new Error("inner decrypt requires a decoded outer header")
    }

    const inner = await writeInnerDecryptArtifacts(
      outputDir,
      input,
      inputPath,
      best,
      resolveInnerTransform(args.transform),
    )
    summary.innerDecrypt = summarizeInnerDecrypt(inner)
  }

  if (args.decryptOffset !== undefined || args.decryptLength !== undefined) {
    if (
      args.decryptOffset === undefined ||
      args.decryptLength === undefined ||
      args.kdf === undefined ||
      args.seedWord === undefined ||
      args.mode === undefined
    ) {
      throw new Error(
        "manual payload decrypt mode requires --decrypt-offset, --decrypt-length, --kdf, --seed-word and --mode",
      )
    }

    const manualTransform = pickTransforms(args.transform)[0]
    if (!manualTransform) {
      throw new Error(`unknown transform: ${args.transform}`)
    }

    const seedBlock = args.seedBlockHex
      ? ensureLength16(hexToBytes(args.seedBlockHex))
      : md5Bytes(args.kdf)
    const manual = decryptPayloadRange(input, {
      offset: args.decryptOffset,
      length: args.decryptLength,
      seedBlock,
      seedWord: args.seedWord,
      mode: args.mode,
      transform: manualTransform,
      progress: createProgressReporter(
        `Decrypting payload 0x${args.decryptOffset.toString(16)}..0x${(args.decryptOffset + args.decryptLength).toString(16)}`,
        Math.max(1, Math.ceil(Math.ceil(args.decryptLength / 4) / 2)),
      ),
    })

    manual.progress.done()

    const outputFile = resolve(
      args.outputFile ?? join(outputDir, `payload-0x${args.decryptOffset.toString(16)}.bin`),
    )
    await writeFile(outputFile, manual.output)

    summary.manualDecrypt = {
      outputFile,
      offset: args.decryptOffset,
      length: args.decryptLength,
      kdf: args.kdf,
      seedWord: toHex(args.seedWord),
      mode: args.mode,
      transform: manualTransform.id,
    }
  }

  const summaryPath = join(outputDir, "summary.json")
  await writeFile(summaryPath, JSON.stringify(summary, null, 2) + "\n")

  if (args.json) {
    console.log(JSON.stringify(summary, null, 2))
    return
  }

  printSummary(encryptedRegions, summaryPath, best, candidates)
}

function parseArgs(argv: string[]): ParsedArgs {
  const parsed: ParsedArgs = {
    outputDir: resolve(process.cwd(), "decode-out"),
    dumpCandidates: 5,
    analyzeHeader: false,
    decryptInner: false,
    json: false,
  }

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    const next = argv[index + 1]

    switch (argument) {
      case "--input":
      case "-i":
        parsed.input = requireValue(argument, next)
        index += 1
        break
      case "--output-dir":
      case "-o":
        parsed.outputDir = resolve(requireValue(argument, next))
        index += 1
        break
      case "--dump-candidates":
        parsed.dumpCandidates = Number.parseInt(requireValue(argument, next), 10)
        index += 1
        break
      case "--transform":
        parsed.transform = requireValue(argument, next)
        index += 1
        break
      case "--analyze-header":
        parsed.analyzeHeader = true
        break
      case "--decrypt-inner":
        parsed.decryptInner = true
        break
      case "--json":
        parsed.json = true
        break
      case "--decrypt-offset":
        parsed.decryptOffset = parseNumber(requireValue(argument, next))
        index += 1
        break
      case "--decrypt-length":
        parsed.decryptLength = parseNumber(requireValue(argument, next))
        index += 1
        break
      case "--kdf":
        parsed.kdf = requireValue(argument, next)
        index += 1
        break
      case "--seed-word":
        parsed.seedWord = parseNumber(requireValue(argument, next))
        index += 1
        break
      case "--mode":
        parsed.mode = parseNumber(requireValue(argument, next))
        index += 1
        break
      case "--output-file":
        parsed.outputFile = resolve(requireValue(argument, next))
        index += 1
        break
      case "--seed-block-hex":
        parsed.seedBlockHex = requireValue(argument, next)
        index += 1
        break
      case "--help":
      case "-h":
        printHelp()
        process.exit(0)
      default:
        throw new Error(`unknown argument: ${argument}`)
    }
  }

  return parsed
}

function printHelp(): void {
  console.log(`Usage:
  bun run wingfw:decode -- --input /path/to/file.wingfw [options]

Outer-header analysis:
  --analyze-header          Also rank outer-header decrypt candidates
  --decrypt-inner           Decrypt the APP and RSRC packed payloads using the
                            manifest fields from the settled outer header
  --input, -i PATH          Input .wingfw file
  --output-dir, -o PATH     Output directory (default: ./decode-out)
  --dump-candidates N       Write the top N header candidates (default: 5)
  --transform ID            Restrict analysis to one transform strategy
  --json                    Print summary JSON to stdout

The tool always performs a binwalk-style entropy scan first and extracts the
likely encrypted regions. Header candidate ranking only runs when
--analyze-header is supplied. --decrypt-inner uses the settled outer-header
transform directly and writes decrypted packed APP/RSRC payloads.

Manual payload decrypt mode:
  --decrypt-offset VALUE    Offset of the encrypted range (decimal or 0x...)
  --decrypt-length VALUE    Length of the encrypted range in bytes
  --kdf STRING              KDF input string; MD5(seed string) becomes the 16-byte seed block
  --seed-word VALUE         32-bit seed word mixed into the context builder
  --mode VALUE              Context mode passed to the recovered builder helper
  --output-file PATH        Where to write the decrypted range
  --seed-block-hex HEX      Override the 16-byte seed block directly instead of MD5(kdf)

Examples:
  bun run wingfw:decode -- --input ../wing-disassembly/wing-compact-release-3.1-20251107.wingfw
  bun run wingfw:decode -- --input file.wingfw --analyze-header --transform loader-delta-seed-update
  bun run wingfw:decode -- --input file.wingfw --decrypt-inner
  bun run wingfw:decode -- --input file.wingfw --decrypt-offset 0x400 --decrypt-length 0x100000 --kdf APPPACK --seed-word 0x12345678 --mode 9 --output-file app.bin
`)
}

function resolveInnerTransform(filter?: string): TransformConfig {
  const [transform] = pickTransforms(filter ?? DEFAULT_TRANSFORM_ID)
  if (!transform) {
    throw new Error(`unknown transform: ${filter ?? DEFAULT_TRANSFORM_ID}`)
  }
  return transform
}

function decodeOuterHeader(
  input: Uint8Array,
  transformFilter?: string,
  progress?: ProgressReporter,
): HeaderCandidate[] {
  const header = input.subarray(0, Math.min(OUTER_HEADER_SIZE, input.length))
  const paddedHeader = padToEight(header)
  const transformList = pickTransforms(transformFilter)

  const candidates: HeaderCandidate[] = []
  let candidateIndex = 0

  for (const seed of OUTER_SEEDS) {
    for (const transform of transformList) {
      candidateIndex += 1
      progress?.update(candidateIndex, `${seed.id} / ${transform.id}`)
      const context = buildContext(seed.mode, seed.seedBlock, seed.seedWord)
      const output = decryptRange(paddedHeader, context, OUTER_HEADER_SIZE >>> 2, transform)
      const headerOutput = output.subarray(0, header.length)
      const analysis = analyzeHeader(headerOutput)

      candidates.push({
        id: `${seed.id}.${transform.id}`,
        seed: seed.id,
        transform: transform.id,
        analysis,
        header: headerOutput,
      })
    }
  }

  candidates.sort((left, right) => right.analysis.score - left.analysis.score)
  return candidates
}

async function writeInnerDecryptArtifacts(
  outputDir: string,
  input: Uint8Array,
  inputPath: string,
  candidate: HeaderCandidate,
  transform: TransformConfig,
): Promise<InnerDecryptResult> {
  const { manifest, source } = resolveInnerManifest(candidate.analysis.metadata, inputPath, input.length)

  const appKdf = `${INNER_KDF_PARTS.join("-")}-${manifest.appSize.toString(16).padStart(8, "0")}`
  const resourceKdf = INNER_KDF_PARTS.join("-")

  const app = decryptPayloadRange(input, {
    offset: OUTER_HEADER_SIZE,
    length: manifest.appPack,
    seedBlock: md5Bytes(appKdf),
    seedWord: manifest.resourceSize,
    mode: 9,
    transform,
    progress: createProgressReporter(
      "Decrypting APP payload",
      Math.max(1, Math.ceil(Math.ceil(manifest.appPack / 4) / 2)),
    ),
  })
  app.progress.done()

  const resourceOffset = alignUp(OUTER_HEADER_SIZE + manifest.appPack, INNER_PACK_ALIGNMENT)
  const resource = decryptPayloadRange(input, {
    offset: resourceOffset,
    length: manifest.resourcePack,
    seedBlock: md5Bytes(resourceKdf),
    seedWord: manifest.appSize,
    mode: 2,
    transform,
    progress: createProgressReporter(
      "Decrypting RSRC payload",
      Math.max(1, Math.ceil(Math.ceil(manifest.resourcePack / 4) / 2)),
    ),
  })
  resource.progress.done()

  const appOutputFile = join(outputDir, "app-packed.decrypted.bin")
  const resourceOutputFile = join(outputDir, "rsrc-packed.decrypted.bin")
  await writeFile(appOutputFile, app.output)
  await writeFile(resourceOutputFile, resource.output)

  const result: InnerDecryptResult = {
    transformId: transform.id,
    manifestSource: source,
    app: {
      offset: OUTER_HEADER_SIZE,
      length: manifest.appPack,
      mode: 9,
      seedWord: manifest.resourceSize,
      kdf: appKdf,
      output: app.output,
      outputFile: appOutputFile,
    },
    resource: {
      offset: resourceOffset,
      length: manifest.resourcePack,
      mode: 2,
      seedWord: manifest.appSize,
      kdf: resourceKdf,
      output: resource.output,
      outputFile: resourceOutputFile,
    },
    manifest,
  }

  await writeFile(join(outputDir, "inner-decrypt.json"), JSON.stringify(summarizeInnerDecrypt(result), null, 2) + "\n")
  return result
}

function parseInnerManifest(metadata: Record<string, string>): InnerManifest {
  return {
    appAddr: parseHexMetadata(metadata, "APPADDR"),
    appPack: parseDecimalMetadata(metadata, "APPPACK"),
    appSize: parseDecimalMetadata(metadata, "APPSIZE"),
    appKey: parseHexByteListMetadata(metadata, "APPKEY"),
    entryPoint: parseHexMetadata(metadata, "ENTRYPOINT"),
    resourcePack: parseDecimalMetadata(metadata, "RSRCPACK"),
    resourceSize: parseDecimalMetadata(metadata, "RSRCSIZE"),
  }
}

function resolveInnerManifest(
  metadata: Record<string, string>,
  inputPath: string,
  inputSize: number,
): { manifest: InnerManifest; source: string } {
  if (hasInnerManifestMetadata(metadata)) {
    return {
      manifest: parseInnerManifest(metadata),
      source: "outer-header",
    }
  }

  const fallback = SETTLED_SAMPLE_MANIFESTS.find(
    (sample) => sample.size === inputSize && sample.fileName === basename(inputPath),
  )
  if (!fallback) {
    throw new Error("outer header is missing APP/RSRC manifest fields")
  }

  return {
    manifest: parseInnerManifest(fallback.metadata),
    source: "settled-sample-manifest",
  }
}

function hasInnerManifestMetadata(metadata: Record<string, string>): boolean {
  return ["APPADDR", "APPKEY", "APPPACK", "APPSIZE", "ENTRYPOINT", "RSRCPACK", "RSRCSIZE"].every(
    (key) => key in metadata,
  )
}

function parseDecimalMetadata(metadata: Record<string, string>, key: string): number {
  const value = metadata[key]
  if (!value) {
    throw new Error(`outer header is missing ${key}`)
  }

  const parsed = Number.parseInt(value, 10)
  if (!Number.isFinite(parsed)) {
    throw new Error(`invalid decimal metadata for ${key}: ${value}`)
  }
  return parsed
}

function parseHexMetadata(metadata: Record<string, string>, key: string): number {
  const value = metadata[key]
  if (!value) {
    throw new Error(`outer header is missing ${key}`)
  }

  const parsed = Number.parseInt(value, 16)
  if (!Number.isFinite(parsed)) {
    throw new Error(`invalid hex metadata for ${key}: ${value}`)
  }
  return parsed >>> 0
}

function parseHexByteListMetadata(metadata: Record<string, string>, key: string): Uint8Array {
  const value = metadata[key]
  if (!value) {
    throw new Error(`outer header is missing ${key}`)
  }

  const bytes = hexToBytes(value)
  if (bytes.length === 0) {
    throw new Error(`invalid byte-list metadata for ${key}: ${value}`)
  }
  return bytes
}

function summarizeInnerDecrypt(result: InnerDecryptResult): Record<string, unknown> {
  const expectedAppDigest = result.manifest.appKey.subarray(0, 16)
  const expectedResourceDigest = result.manifest.appKey.subarray(16, 32)
  const resourceTargetAddress =
    (result.manifest.appAddr + alignUp(result.manifest.appSize, INNER_PACK_ALIGNMENT)) >>> 0

  return {
    app: {
      offset: toHex(result.app.offset),
      length: result.app.length,
      mode: result.app.mode,
      seedWord: toHex(result.app.seedWord),
      kdf: result.app.kdf,
      outputFile: result.app.outputFile,
      targetAddress: toHex(result.manifest.appAddr),
      expectedExpandedSize: result.manifest.appSize,
      expectedMd5: bytesToHex(expectedAppDigest),
    },
    resource: {
      offset: toHex(result.resource.offset),
      length: result.resource.length,
      mode: result.resource.mode,
      seedWord: toHex(result.resource.seedWord),
      kdf: result.resource.kdf,
      outputFile: result.resource.outputFile,
      targetAddress: toHex(resourceTargetAddress),
      expectedExpandedSize: result.manifest.resourceSize,
      expectedMd5: bytesToHex(expectedResourceDigest),
    },
    entryPoint: toHex(result.manifest.entryPoint),
    manifestSource: result.manifestSource,
    transform: result.transformId,
  }
}

function scanEntropy(
  input: Uint8Array,
  windowSize = ENTROPY_WINDOW_SIZE,
  progress?: ProgressReporter,
): EntropyWindow[] {
  const windows: EntropyWindow[] = []
  const totalWindows = Math.ceil(input.length / windowSize)
  let completed = 0

  for (let offset = 0; offset < input.length; offset += windowSize) {
    const end = Math.min(input.length, offset + windowSize)
    const chunk = input.subarray(offset, end)
    const histogram = new Uint32Array(256)

    for (const value of chunk) {
      histogram[value] += 1
    }

    let entropy = 0
    for (const count of histogram) {
      if (count === 0) {
        continue
      }
      const probability = count / chunk.length
      entropy -= probability * Math.log2(probability)
    }

    windows.push({ offset, end, entropy })
    completed += 1
    progress?.update(completed, `${toHex(offset)}-${toHex(end)}`)
  }

  if (completed === 0) {
    progress?.update(totalWindows)
  }

  return windows
}

function findEncryptedRegions(
  windows: EntropyWindow[],
  highThreshold = ENTROPY_HIGH_THRESHOLD,
  lowThreshold = ENTROPY_LOW_THRESHOLD,
): EncryptedRegion[] {
  const regions: EncryptedRegion[] = []
  let currentStart = -1
  let currentEnd = -1
  let maxEntropy = 0
  let entropySum = 0
  let windowCount = 0

  for (const window of windows) {
    if (currentStart === -1) {
      if (window.entropy >= highThreshold) {
        currentStart = window.offset
        currentEnd = window.end
        maxEntropy = window.entropy
        entropySum = window.entropy
        windowCount = 1
      }
      continue
    }

    if (window.entropy >= lowThreshold) {
      currentEnd = window.end
      maxEntropy = Math.max(maxEntropy, window.entropy)
      entropySum += window.entropy
      windowCount += 1
      continue
    }

    regions.push({
      offset: currentStart,
      end: currentEnd,
      size: currentEnd - currentStart,
      maxEntropy,
      averageEntropy: entropySum / Math.max(1, windowCount),
    })

    currentStart = -1
    currentEnd = -1
    maxEntropy = 0
    entropySum = 0
    windowCount = 0
  }

  if (currentStart !== -1) {
    regions.push({
      offset: currentStart,
      end: currentEnd,
      size: currentEnd - currentStart,
      maxEntropy,
      averageEntropy: entropySum / Math.max(1, windowCount),
    })
  }

  return regions
}

function analyzeHeader(buffer: Uint8Array): HeaderAnalysis {
  const text = toAscii(buffer)
  const cleaned = text.replace(/[^\x20-\x7e~]+/g, "\n")
  const metadata = parseMetadata(cleaned)
  const tokenHits = KNOWN_TOKENS.filter((token) => cleaned.includes(token))
  const printableRatio =
    Array.from(buffer).filter((value) => value === 0x09 || value === 0x0a || value === 0x0d || (value >= 0x20 && value <= 0x7e)).length /
    Math.max(1, buffer.length)

  const equalsCount = cleaned.split("=").length - 1
  const tildeCount = cleaned.split("~").length - 1
  const metadataCount = Object.keys(metadata).length
  const score =
    tokenHits.length * 60 +
    metadataCount * 25 +
    equalsCount * 3 +
    tildeCount * 2 +
    printableRatio * 25

  return {
    printableRatio,
    tokenHits,
    metadata,
    score,
    text: cleaned,
  }
}

function parseMetadata(text: string): Record<string, string> {
  const metadata: Record<string, string> = {}
  const knownKeys = [
    "PROJECT",
    "VERSION",
    "CDATE",
    "DEVTYPE",
    "DEV",
    "APPPACK",
    "APPADDR",
    "APPKEY",
    "APPSIZE",
    "RSRCPACK",
    "RSRCSIZE",
    "ENTRYPOINT",
  ]

  for (const key of knownKeys) {
    const match = text.match(new RegExp(`${key}=([^~\\n\\r\\0]+)`))
    if (match) {
      metadata[key] = match[1].trim()
    }
  }

  for (const segment of text.split(/[~\n\r]+/)) {
    const match = segment.match(/^([A-Z][A-Z0-9_.-]{2,})=([^\0]+)$/)
    if (!match) {
      continue
    }
    metadata[match[1]] = match[2].trim()
  }

  return metadata
}

function buildContext(mode: number, seedBlock: Uint8Array, seedWord: number): CipherContext {
  const normalizedSeedBlock = ensureLength16(seedBlock)
  const initialWords: [number, number, number, number] = [
    readU32LE(normalizedSeedBlock, 0),
    readU32LE(normalizedSeedBlock, 4),
    readU32LE(normalizedSeedBlock, 8),
    readU32LE(normalizedSeedBlock, 12),
  ]
  const seedBytes: [number, number, number, number] = [
    (seedWord >>> 24) & 0xff,
    (seedWord >>> 16) & 0xff,
    (seedWord >>> 8) & 0xff,
    seedWord & 0xff,
  ]
  const keyWords: [number, number, number, number] = [
    (initialWords[0] + seedBytes[0]) >>> 0,
    (initialWords[1] + seedBytes[1]) >>> 0,
    (initialWords[2] + seedBytes[2]) >>> 0,
    (initialWords[3] + seedBytes[3]) >>> 0,
  ]

  return {
    mode: mode >>> 0,
    seedWord: seedWord >>> 0,
    seedBytes,
    initialWords,
    keyWords,
  }
}

function decryptPayloadRange(
  input: Uint8Array,
  options: {
    offset: number
    length: number
    seedBlock: Uint8Array
    seedWord: number
    mode: number
    transform: TransformConfig
    progress: ProgressReporter
  },
): { output: Uint8Array; progress: ProgressReporter } {
  const start = options.offset
  const end = start + options.length
  if (start < 0 || end > input.length) {
    throw new Error(`decrypt range 0x${start.toString(16)}..0x${end.toString(16)} is outside the file`) 
  }

  const source = input.subarray(start, end)
  const padded = padToEight(source)
  const context = buildContext(options.mode, options.seedBlock, options.seedWord)
  const output = decryptRange(
    padded,
    context,
    Math.ceil(source.length / 4),
    options.transform,
    options.progress,
  )
  return { output: output.subarray(0, source.length), progress: options.progress }
}

function decryptRange(
  data: Uint8Array,
  context: CipherContext,
  wordCount: number,
  transform: TransformConfig,
  progress?: ProgressReporter,
): Uint8Array {
  const output = Uint8Array.from(data)
  let byteOffset = 0
  let remainingWords = wordCount >>> 0
  const totalPairs = Math.max(1, Math.ceil(wordCount / 2))
  let completedPairs = 0

  while (remainingWords > 1 && byteOffset + 8 <= output.length) {
    let left = readU32LE(output, byteOffset)
    let right = readU32LE(output, byteOffset + 4)

    if (transform.rounds === "loader") {
      const rounds = ((remainingWords - 1) & ~1) >>> 0
      let sum = (Math.imul(transform.delta >>> 0, rounds) + LOADER_SUM_END) >>> 0

      for (let round = 0; round < rounds; round += 1) {
        const mixRight =
          (((((left >>> 5) ^ ((left << 4) >>> 0)) + left) >>> 0) ^
            ((sum + context.keyWords[(sum >>> 11) & 3]) >>> 0)) >>>
          0
        right = (right - mixRight) >>> 0

        sum = (sum - (transform.delta >>> 0)) >>> 0

        const mixLeft =
          (((((right >>> 5) ^ ((right << 4) >>> 0)) + right) >>> 0) ^
            ((sum + context.keyWords[sum & 3]) >>> 0)) >>>
          0
        left = (left - mixLeft) >>> 0
      }
    } else {
      let sum = Math.imul(transform.delta >>> 0, 32) >>> 0
      for (let round = 0; round < 32; round += 1) {
        right =
          (right -
            (((((left << 4) >>> 0) ^ (left >>> 5)) + left) ^
              ((sum + context.keyWords[(sum >>> 11) & 3]) >>> 0))) >>>
          0
        sum = (sum - (transform.delta >>> 0)) >>> 0
        left =
          (left -
            (((((right << 4) >>> 0) ^ (right >>> 5)) + right) ^
              ((sum + context.keyWords[sum & 3]) >>> 0))) >>>
          0
      }
    }

    writeU32LE(output, byteOffset, left)
    writeU32LE(output, byteOffset + 4, right)

    byteOffset += 8
    remainingWords -= 2
    updateContext(context, transform.updateMode)
    completedPairs += 1
    progress?.update(completedPairs, transform.id)
  }

  if (completedPairs === 0) {
    progress?.update(totalPairs, transform.id)
  }

  return output
}

function updateContext(context: CipherContext, mode: UpdateMode): void {
  if (mode === "none") {
    return
  }

  const multiplier = mode === "mode-byte" ? context.mode : 1
  context.keyWords = [
    (context.keyWords[0] + Math.imul(multiplier, context.seedBytes[0])) >>> 0,
    (context.keyWords[1] + Math.imul(multiplier, context.seedBytes[1])) >>> 0,
    (context.keyWords[2] + Math.imul(multiplier, context.seedBytes[2])) >>> 0,
    (context.keyWords[3] + Math.imul(multiplier, context.seedBytes[3])) >>> 0,
  ]
}

async function writeOuterArtifacts(
  outputDir: string,
  best: HeaderCandidate,
  candidates: HeaderCandidate[],
  dumpCandidates: number,
): Promise<void> {
  await writeFile(join(outputDir, "best-header.bin"), best.header)
  await writeFile(join(outputDir, "best-header.txt"), best.analysis.text + "\n")
  await writeFile(
    join(outputDir, "header-candidates.json"),
    JSON.stringify(candidates.map(summarizeCandidate), null, 2) + "\n",
  )

  const count = Math.max(1, dumpCandidates)
  for (const [index, candidate] of candidates.slice(0, count).entries()) {
    const prefix = `${String(index + 1).padStart(2, "0")}-${candidate.id}`
    await writeFile(join(outputDir, `${prefix}.bin`), candidate.header)
    await writeFile(join(outputDir, `${prefix}.txt`), candidate.analysis.text + "\n")
  }
}

async function writeEncryptedRegionArtifacts(
  outputDir: string,
  input: Uint8Array,
  windows: EntropyWindow[],
  regions: EncryptedRegion[],
): Promise<void> {
  await writeFile(
    join(outputDir, "entropy-windows.json"),
    JSON.stringify(
      windows.map((window) => ({
        offset: toHex(window.offset),
        end: toHex(window.end),
        entropy: Number(window.entropy.toFixed(6)),
      })),
      null,
      2,
    ) + "\n",
  )

  await writeFile(
    join(outputDir, "encrypted-regions.json"),
    JSON.stringify(
      regions.map((region) => ({
        offset: toHex(region.offset),
        end: toHex(region.end),
        size: region.size,
        maxEntropy: Number(region.maxEntropy.toFixed(6)),
        averageEntropy: Number(region.averageEntropy.toFixed(6)),
      })),
      null,
      2,
    ) + "\n",
  )

  for (const [index, region] of regions.entries()) {
    const fileName = `encrypted-region-${String(index + 1).padStart(2, "0")}-${toHex(region.offset)}-${toHex(region.end)}.bin`
    await writeFile(join(outputDir, fileName), input.subarray(region.offset, region.end))
  }
}

function summarizeCandidate(candidate: HeaderCandidate): Record<string, unknown> {
  return {
    id: candidate.id,
    seed: candidate.seed,
    transform: candidate.transform,
    score: Number(candidate.analysis.score.toFixed(3)),
    printableRatio: Number(candidate.analysis.printableRatio.toFixed(6)),
    tokenHits: candidate.analysis.tokenHits,
    metadata: candidate.analysis.metadata,
  }
}

function printSummary(
  encryptedRegions: EncryptedRegion[],
  summaryPath: string,
  best?: HeaderCandidate,
  candidates: HeaderCandidate[] = [],
): void {
  const summaryDir = resolve(summaryPath, "..")
  const encryptedRegionsPath = join(summaryDir, "encrypted-regions.json")

  console.log(`Likely encrypted regions: ${encryptedRegionsPath}`)
  for (const region of encryptedRegions) {
    console.log(
      `  ${toHex(region.offset)}-${toHex(region.end)} size=${region.size} avgEntropy=${region.averageEntropy.toFixed(3)} maxEntropy=${region.maxEntropy.toFixed(3)}`,
    )
  }

  if (!best) {
    console.log(`Wrote extraction artifacts to ${summaryPath}`)
    return
  }

  console.log(`Best header candidate: ${best.id}`)
  console.log(`  score: ${best.analysis.score.toFixed(3)}`)
  console.log(`  printable ratio: ${best.analysis.printableRatio.toFixed(3)}`)

  if (best.analysis.tokenHits.length > 0) {
    console.log(`  token hits: ${best.analysis.tokenHits.join(", ")}`)
  }

  const metadataEntries = Object.entries(best.analysis.metadata)
  if (metadataEntries.length > 0) {
    console.log("  parsed metadata:")
    for (const [key, value] of metadataEntries) {
      console.log(`    ${key}=${value}`)
    }
  }

  console.log("Top strategies:")
  for (const candidate of candidates.slice(0, 3)) {
    console.log(
      `  ${candidate.id.padEnd(36)} score=${candidate.analysis.score.toFixed(3)} printable=${candidate.analysis.printableRatio.toFixed(3)}`,
    )
  }

  console.log(`Wrote decoder artifacts to ${summaryPath}`)
}

function pickTransforms(filter?: string): TransformConfig[] {
  if (!filter) {
    return TRANSFORMS
  }

  const transforms = TRANSFORMS.filter((transform) => transform.id === filter)
  if (transforms.length === 0) {
    throw new Error(`unknown transform: ${filter}`)
  }
  return transforms
}

function parseNumber(value: string): number {
  if (/^0x/i.test(value)) {
    return Number.parseInt(value, 16)
  }
  return Number.parseInt(value, 10)
}

function requireValue(flag: string, value: string | undefined): string {
  if (value === undefined) {
    throw new Error(`${flag} requires a value`)
  }
  return value
}

function md5Bytes(text: string): Uint8Array {
  return new Uint8Array(createHash("md5").update(text).digest())
}

function padToEight(data: Uint8Array): Uint8Array {
  const paddedLength = alignUp(data.length, 8)
  if (paddedLength === data.length) {
    return Uint8Array.from(data)
  }

  const output = new Uint8Array(paddedLength)
  output.set(data)
  return output
}

function alignUp(value: number, alignment: number): number {
  return (value + alignment - 1) & ~(alignment - 1)
}

function ensureLength16(value: Uint8Array): Uint8Array {
  if (value.length === 16) {
    return value
  }

  const result = new Uint8Array(16)
  result.set(value.subarray(0, 16))
  return result
}

function readU32LE(buffer: Uint8Array, offset: number): number {
  return (
    buffer[offset]! |
    (buffer[offset + 1]! << 8) |
    (buffer[offset + 2]! << 16) |
    (buffer[offset + 3]! << 24)
  ) >>> 0
}

function writeU32LE(buffer: Uint8Array, offset: number, value: number): void {
  buffer[offset] = value & 0xff
  buffer[offset + 1] = (value >>> 8) & 0xff
  buffer[offset + 2] = (value >>> 16) & 0xff
  buffer[offset + 3] = (value >>> 24) & 0xff
}

function toAscii(buffer: Uint8Array): string {
  return Array.from(buffer, (value) => {
    if (value === 0x09 || value === 0x0a || value === 0x0d) {
      return String.fromCharCode(value)
    }
    if (value >= 0x20 && value <= 0x7e) {
      return String.fromCharCode(value)
    }
    return "\n"
  }).join("")
}

function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.replace(/[^0-9a-f]/gi, "")
  if (normalized.length % 2 !== 0) {
    throw new Error(`invalid hex string length: ${hex}`)
  }

  const output = new Uint8Array(normalized.length / 2)
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16)
  }
  return output
}

function bytesToHex(buffer: Uint8Array): string {
  return Array.from(buffer, (value) => value.toString(16).padStart(2, "0")).join("")
}

function toHex(value: number): string {
  return `0x${value.toString(16).padStart(8, "0")}`
}

function createProgressReporter(label: string, total: number): ProgressReporter {
  const normalizedTotal = Math.max(1, total)
  let lastPercent = -1
  let lastDetail = ""

  return {
    update(current: number, detail?: string): void {
      const bounded = Math.max(0, Math.min(current, normalizedTotal))
      const percent = Math.floor((bounded / normalizedTotal) * 100)
      const safeDetail = detail ?? ""

      if (percent === lastPercent && safeDetail === lastDetail) {
        return
      }

      lastPercent = percent
      lastDetail = safeDetail
      const suffix = safeDetail.length > 0 ? ` - ${safeDetail}` : ""
      process.stderr.write(`\r${label}: ${String(percent).padStart(3, " ")}% (${bounded}/${normalizedTotal})${suffix}`)
    },
    done(detail?: string): void {
      this.update(normalizedTotal, detail)
      process.stderr.write("\n")
    },
  }
}

void main()
