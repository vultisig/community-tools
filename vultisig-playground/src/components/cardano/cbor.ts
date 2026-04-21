/**
 * Minimal canonical-CBOR encoder for building Cardano transactions.
 *
 * Cardano expects deterministic CBOR for tx bodies so that the body hash is
 * stable. We hand-roll the primitives here (rather than relying on cbor-x)
 * because cbor-x does not guarantee canonical map ordering or length forms.
 *
 * cbor-x is used on the decode side only, where canonical form doesn't matter.
 */

const concat = (parts: Uint8Array[]): Uint8Array => {
  let total = 0
  for (const p of parts) total += p.length
  const out = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

/**
 * Encodes a CBOR head byte for a given major type and unsigned argument,
 * using the shortest valid length form.
 */
const encodeHead = (majorType: number, argument: bigint): Uint8Array => {
  const mt = majorType << 5
  if (argument < 0n) {
    throw new Error(`CBOR head argument must be non-negative: ${argument}`)
  }
  if (argument < 24n) {
    return new Uint8Array([mt | Number(argument)])
  }
  if (argument < 0x100n) {
    return new Uint8Array([mt | 24, Number(argument)])
  }
  if (argument < 0x10000n) {
    const n = Number(argument)
    return new Uint8Array([mt | 25, (n >> 8) & 0xff, n & 0xff])
  }
  if (argument < 0x100000000n) {
    const n = Number(argument)
    return new Uint8Array([
      mt | 26,
      (n >>> 24) & 0xff,
      (n >>> 16) & 0xff,
      (n >>> 8) & 0xff,
      n & 0xff,
    ])
  }
  const buf = new Uint8Array(9)
  buf[0] = mt | 27
  const view = new DataView(buf.buffer)
  view.setBigUint64(1, argument, false)
  return buf
}

export const cborUint = (value: bigint | number): Uint8Array => {
  const v = typeof value === 'bigint' ? value : BigInt(value)
  if (v < 0n) throw new Error(`cborUint: negative value ${v}`)
  return encodeHead(0, v)
}

export const cborNegInt = (value: bigint | number): Uint8Array => {
  const v = typeof value === 'bigint' ? value : BigInt(value)
  if (v >= 0n) throw new Error(`cborNegInt: non-negative value ${v}`)
  return encodeHead(1, -1n - v)
}

export const cborInt = (value: bigint | number): Uint8Array => {
  const v = typeof value === 'bigint' ? value : BigInt(value)
  return v < 0n ? cborNegInt(v) : cborUint(v)
}

export const cborBytes = (bytes: Uint8Array): Uint8Array =>
  concat([encodeHead(2, BigInt(bytes.length)), bytes])

export const cborText = (s: string): Uint8Array => {
  const bytes = new TextEncoder().encode(s)
  return concat([encodeHead(3, BigInt(bytes.length)), bytes])
}

export const cborArray = (items: Uint8Array[]): Uint8Array =>
  concat([encodeHead(4, BigInt(items.length)), ...items])

export const cborMap = (
  entries: Array<[Uint8Array, Uint8Array]>
): Uint8Array => {
  const parts: Uint8Array[] = [encodeHead(5, BigInt(entries.length))]
  for (const [k, v] of entries) {
    parts.push(k, v)
  }
  return concat(parts)
}

export const cborBool = (b: boolean): Uint8Array =>
  new Uint8Array([b ? 0xf5 : 0xf4])

export const cborNull = (): Uint8Array => new Uint8Array([0xf6])

export const toHex = (bytes: Uint8Array): string => {
  let hex = ''
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0')
  }
  return hex
}

export const fromHex = (hex: string): Uint8Array => {
  const clean = hex.replace(/^0x/i, '').trim()
  if (clean.length % 2 !== 0) {
    throw new Error('fromHex: odd-length hex string')
  }
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
    if (Number.isNaN(byte)) {
      throw new Error(`fromHex: invalid hex byte at ${i * 2}`)
    }
    out[i] = byte
  }
  return out
}
