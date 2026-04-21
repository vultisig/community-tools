import { useState, useEffect } from 'react'
import nacl from 'tweetnacl'
import { Buffer } from 'buffer'
import type { TonConnectBridge, ConnectEventSuccess, TonAddrItemReply } from './types'

interface SignDataMethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

type SignDataType = 'text' | 'binary' | 'cell'

interface SignDataResult {
  signature: string
  address: string
  timestamp: number
  domain: string
  payload: { type: string; text?: string; bytes?: string; schema?: string; cell?: string }
}

/**
 * Parses a TON raw address (workchain:hash) into workchain int and 32-byte hash buffer.
 */
function parseRawAddress(raw: string): { workchain: number; hash: Uint8Array } {
  const parts = raw.split(':')
  if (parts.length !== 2) throw new Error('Invalid raw address format')
  const workchain = parseInt(parts[0], 10)
  const hash = new Uint8Array(Buffer.from(parts[1], 'hex'))
  if (hash.length !== 32) throw new Error('Invalid address hash length')
  return { workchain, hash }
}

/**
 * Builds the SHA-256 hash for text or binary signData payloads per TonConnect v2 spec.
 *
 * Layout: 0xffff ++ "ton-connect/sign-data/" ++ workchain(4 BE) ++ address_hash(32)
 *       ++ domain_length(4 BE) ++ domain_bytes ++ timestamp(8 BE)
 *       ++ type_prefix("txt"|"bin") ++ payload_length(4 BE) ++ payload_data
 */
async function buildTextBinaryHash(
  address: string,
  domain: string,
  timestamp: number,
  type: 'text' | 'binary',
  payloadData: Uint8Array
): Promise<Uint8Array> {
  const { workchain, hash: addressHash } = parseRawAddress(address)

  const workchainBuf = new ArrayBuffer(4)
  new DataView(workchainBuf).setInt32(0, workchain, false)

  const domainBytes = new TextEncoder().encode(domain)
  const domainLengthBuf = new ArrayBuffer(4)
  new DataView(domainLengthBuf).setUint32(0, domainBytes.length, false)

  const timestampBuf = new ArrayBuffer(8)
  new DataView(timestampBuf).setBigUint64(0, BigInt(timestamp), false)

  const typePrefix = new TextEncoder().encode(type === 'text' ? 'txt' : 'bin')

  const payloadLengthBuf = new ArrayBuffer(4)
  new DataView(payloadLengthBuf).setUint32(0, payloadData.length, false)

  const parts = [
    new Uint8Array([0xff, 0xff]),
    new TextEncoder().encode('ton-connect/sign-data/'),
    new Uint8Array(workchainBuf),
    addressHash,
    new Uint8Array(domainLengthBuf),
    domainBytes,
    new Uint8Array(timestampBuf),
    typePrefix,
    new Uint8Array(payloadLengthBuf),
    payloadData,
  ]

  const totalLength = parts.reduce((sum, p) => sum + p.length, 0)
  const message = new Uint8Array(totalLength)
  let offset = 0
  for (const part of parts) {
    message.set(part, offset)
    offset += part.length
  }

  const hashBuffer = await crypto.subtle.digest('SHA-256', message)
  return new Uint8Array(hashBuffer)
}

/**
 * Verifies an ed25519 signature from a TonConnect signData result.
 * Supports text and binary payload types.
 */
async function verifySignature(
  result: SignDataResult,
  publicKeyHex: string,
  originalPayload: { type: SignDataType; text: string; bytes: string }
): Promise<{ valid: boolean; detail: string }> {
  if (result.payload.type === 'cell') {
    return {
      valid: false,
      detail: 'Cell payload verification requires @ton/core (not available). Signature cannot be verified locally.',
    }
  }

  const signatureBytes = new Uint8Array(Buffer.from(result.signature, 'base64'))
  if (signatureBytes.length !== 64) {
    return { valid: false, detail: `Invalid signature length: ${signatureBytes.length} (expected 64)` }
  }

  const publicKeyBytes = new Uint8Array(Buffer.from(publicKeyHex, 'hex'))
  if (publicKeyBytes.length !== 32) {
    return { valid: false, detail: `Invalid public key length: ${publicKeyBytes.length} (expected 32)` }
  }

  let payloadData: Uint8Array
  if (result.payload.type === 'text') {
    payloadData = new TextEncoder().encode(originalPayload.text)
  } else {
    payloadData = new Uint8Array(Buffer.from(originalPayload.bytes, 'base64'))
  }

  const hash = await buildTextBinaryHash(
    result.address,
    result.domain,
    result.timestamp,
    result.payload.type as 'text' | 'binary',
    payloadData
  )

  const valid = nacl.sign.detached.verify(hash, signatureBytes, publicKeyBytes)
  return {
    valid,
    detail: valid
      ? 'Signature is valid (ed25519 over SHA-256 hash)'
      : 'Signature verification failed',
  }
}

export function SignDataMethod({ provider, onResult, onError }: SignDataMethodProps) {
  const [dataType, setDataType] = useState<SignDataType>('text')
  const [text, setText] = useState('')
  const [bytes, setBytes] = useState('')
  const [schema, setSchema] = useState('')
  const [cell, setCell] = useState('')
  const [publicKey, setPublicKey] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const bridge = provider as TonConnectBridge
    if (!bridge?.restoreConnection) return
    bridge.restoreConnection().then((event) => {
      if (event.event !== 'connect') return
      const addrItem = (event as ConnectEventSuccess).payload.items.find(
        (item): item is TonAddrItemReply => item.name === 'ton_addr'
      )
      if (addrItem?.publicKey) {
        setPublicKey(addrItem.publicKey)
      }
    }).catch(() => {})
  }, [provider])
  const [verifying, setVerifying] = useState(false)
  const [verificationResult, setVerificationResult] = useState<{
    valid: boolean
    detail: string
  } | null>(null)
  const [lastResult, setLastResult] = useState<SignDataResult | null>(null)
  const [lastPayload, setLastPayload] = useState<{
    type: SignDataType
    text: string
    bytes: string
  } | null>(null)

  const loadExample = () => {
    setDataType('text')
    setText('Hello, TON!')
    setBytes('')
    setSchema('')
    setCell('')
    setVerificationResult(null)
    setLastResult(null)
  }

  const handleSignData = async () => {
    const bridge = provider as TonConnectBridge
    if (!bridge?.send || typeof bridge.send !== 'function') {
      onError('TonConnect bridge or send method not available')
      return
    }

    let payload: Record<string, string>

    if (dataType === 'text') {
      if (!text.trim()) {
        onError('Text content is required')
        return
      }
      payload = { type: 'text', text: text.trim() }
    } else if (dataType === 'binary') {
      if (!bytes.trim()) {
        onError('Base64-encoded bytes are required')
        return
      }
      payload = { type: 'binary', bytes: bytes.trim() }
    } else {
      if (!schema.trim()) {
        onError('TL-B schema is required')
        return
      }
      if (!cell.trim()) {
        onError('Base64-encoded cell BOC is required')
        return
      }
      payload = { type: 'cell', schema: schema.trim(), cell: cell.trim() }
    }

    setLoading(true)
    setVerificationResult(null)
    setLastResult(null)
    try {
      const result = await bridge.send({
        method: 'signData',
        params: [JSON.stringify(payload)],
        id: Date.now().toString(),
      })

      const resultObj = result as { result?: SignDataResult } | SignDataResult
      const signDataResult = 'result' in resultObj && resultObj.result
        ? resultObj.result
        : resultObj as SignDataResult

      if (signDataResult?.signature) {
        setLastResult(signDataResult)
        setLastPayload({ type: dataType, text: text.trim(), bytes: bytes.trim() })
      }

      onResult(result)
    } catch (err) {
      onError((err as Error).message || 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  const handleVerify = async () => {
    if (!lastResult || !lastPayload) {
      onError('No signData result to verify. Sign data first.')
      return
    }
    if (!publicKey.trim()) {
      onError('Public key (hex) is required for verification. Get it from the connect result (ton_addr.publicKey).')
      return
    }

    setVerifying(true)
    try {
      const result = await verifySignature(lastResult, publicKey.trim(), lastPayload)
      setVerificationResult(result)
    } catch (err) {
      setVerificationResult({
        valid: false,
        detail: `Verification error: ${(err as Error).message}`,
      })
    } finally {
      setVerifying(false)
    }
  }

  const canSubmit =
    !loading &&
    (dataType === 'text'
      ? text.trim().length > 0
      : dataType === 'binary'
        ? bytes.trim().length > 0
        : schema.trim().length > 0 && cell.trim().length > 0)

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-600">
        Sign arbitrary data using TonConnect v2 signData. Supports text, binary, and cell payload
        types. Returns a signature, address, timestamp, and domain.
      </p>

      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          Public Key (hex)
        </label>
        <input
          type="text"
          value={publicKey}
          onChange={(e) => {
            setPublicKey(e.target.value)
            setVerificationResult(null)
          }}
          placeholder="32-byte hex public key from connect result (ton_addr.publicKey)"
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <p className="text-xs text-gray-500 mt-1">
          Used for signature verification. Available in the connect response under ton_addr.publicKey.
        </p>
      </div>

      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">Payload Type</label>
        <div className="flex gap-2">
          {(['text', 'binary', 'cell'] as const).map((t) => (
            <button
              key={t}
              onClick={() => {
                setDataType(t)
                setVerificationResult(null)
                setLastResult(null)
              }}
              className={`px-3 py-1.5 text-xs rounded border transition-colors ${
                dataType === t
                  ? 'bg-blue-600 text-white border-blue-600'
                  : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
              }`}
            >
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </button>
          ))}
          <button
            onClick={loadExample}
            className="ml-auto px-2 py-1.5 text-xs bg-gray-100 border border-gray-300 text-gray-700 rounded hover:bg-gray-200 transition-colors"
          >
            Load Example
          </button>
        </div>
      </div>

      {dataType === 'text' && (
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            Text <span className="text-red-500">*</span>
          </label>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Enter text to sign (UTF-8)"
            className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y"
            rows={3}
          />
          <p className="text-xs text-gray-500 mt-1">Plain text message to sign.</p>
        </div>
      )}

      {dataType === 'binary' && (
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            Bytes (Base64) <span className="text-red-500">*</span>
          </label>
          <textarea
            value={bytes}
            onChange={(e) => setBytes(e.target.value)}
            placeholder="Base64-encoded binary data"
            className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y"
            rows={3}
          />
          <p className="text-xs text-gray-500 mt-1">Base64-encoded binary payload to sign.</p>
        </div>
      )}

      {dataType === 'cell' && (
        <div className="space-y-2">
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">
              TL-B Schema <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={schema}
              onChange={(e) => setSchema(e.target.value)}
              placeholder="e.g., some_prefix#12345678 field1:uint32 field2:uint64 = SomeType"
              className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <p className="text-xs text-gray-500 mt-1">
              TL-B schema string. Its CRC32 hash is used in the cell message.
            </p>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">
              Cell (Base64 BOC) <span className="text-red-500">*</span>
            </label>
            <textarea
              value={cell}
              onChange={(e) => setCell(e.target.value)}
              placeholder="Base64-encoded BOC of the cell payload"
              className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y"
              rows={3}
            />
            <p className="text-xs text-gray-500 mt-1">
              Base64-encoded Bag of Cells containing the payload cell.
            </p>
          </div>
        </div>
      )}

      <button
        onClick={handleSignData}
        disabled={!canSubmit}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Signing...' : 'Sign Data'}
      </button>

      {lastResult && (
        <div className="border-t border-gray-200 pt-3 space-y-2">
          <button
            onClick={handleVerify}
            disabled={verifying || !publicKey.trim()}
            className="w-full px-4 py-2 text-sm bg-green-600 text-white rounded hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
          >
            {verifying ? 'Verifying...' : 'Verify Signature'}
          </button>
          {!publicKey.trim() && (
            <p className="text-xs text-amber-600">
              Enter the public key above to enable verification.
            </p>
          )}

          {verificationResult && (
            <div
              className={`p-3 rounded-md text-xs font-mono ${
                verificationResult.valid
                  ? 'bg-green-50 border border-green-200 text-green-800'
                  : 'bg-red-50 border border-red-200 text-red-800'
              }`}
            >
              <span className="font-semibold">
                {verificationResult.valid ? 'VALID' : 'INVALID'}:
              </span>{' '}
              {verificationResult.detail}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
