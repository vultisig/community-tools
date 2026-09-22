import { useState } from 'react'

interface SignTypedDataV4MethodProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}

const LONG_DESCRIPTION = "This is a deliberately large typed data payload to test eth_signTypedData_v4 with messages that are several times bigger than a minimal example. It includes multiple nested types, arrays, and long string fields to simulate real-world order or permit structures used in DeFi and NFT applications. "
const LONG_DESCRIPTION_X15 = LONG_DESCRIPTION.repeat(15)

const LONG_TITLE = "Large EIP-712 Signed Order Example for Testing Very Long Payloads in Wallets and Signers "
const LONG_TITLE_X15 = LONG_TITLE.repeat(15)

const LONG_CONTENTS_PARAGRAPH = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. "
const LONG_CONTENTS_X15 = LONG_CONTENTS_PARAGRAPH.repeat(15)

const DEFAULT_TYPED_DATA = `{
  "domain": {
    "name": "Large EIP-712 Example DApp for Testing Very Long Domain Names and Payloads in Production and Staging Environments with Extended Metadata",
    "version": "2",
    "chainId": 1,
    "verifyingContract": "0x0000000000000000000000000000000000000000",
    "salt": "0x0000000000000000000000000000000000000000000000000000000000000000"
  },
  "primaryType": "Order",
  "types": {
    "EIP712Domain": [
      { "name": "name", "type": "string" },
      { "name": "version", "type": "string" },
      { "name": "chainId", "type": "uint256" },
      { "name": "verifyingContract", "type": "address" },
      { "name": "salt", "type": "bytes32" }
    ],
    "Order": [
      { "name": "maker", "type": "Person" },
      { "name": "taker", "type": "Person" },
      { "name": "items", "type": "OrderItem[]" },
      { "name": "metadata", "type": "OrderMetadata" },
      { "name": "nonce", "type": "uint256" },
      { "name": "expiry", "type": "uint256" },
      { "name": "contents", "type": "string" }
    ],
    "OrderItem": [
      { "name": "token", "type": "address" },
      { "name": "amount", "type": "uint256" },
      { "name": "id", "type": "bytes32" }
    ],
    "OrderMetadata": [
      { "name": "title", "type": "string" },
      { "name": "description", "type": "string" },
      { "name": "tags", "type": "string[]" }
    ],
    "Person": [
      { "name": "name", "type": "string" },
      { "name": "wallet", "type": "address" },
      { "name": "email", "type": "string" }
    ]
  },
  "message": {
    "maker": {
      "name": "Alice Maker of Very Long Signed Orders and Permits for EIP-712 Testing in Production and Staging",
      "wallet": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "email": "alice.very.long.example.email.address.for.eip712.large.payload@example.com"
    },
    "taker": {
      "name": "Bob Taker of Very Long Signed Orders and Permits for EIP-712 Testing in Production and Staging",
      "wallet": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "email": "bob.very.long.example.email.address.for.eip712.large.payload@example.com"
    },
    "items": [
      { "token": "0x1111111111111111111111111111111111111111", "amount": "1000000000000000000", "id": "0x0000000000000000000000000000000000000000000000000000000000000001" },
      { "token": "0x2222222222222222222222222222222222222222", "amount": "2000000000000000000", "id": "0x0000000000000000000000000000000000000000000000000000000000000002" },
      { "token": "0x3333333333333333333333333333333333333333", "amount": "3000000000000000000", "id": "0x0000000000000000000000000000000000000000000000000000000000000003" },
      { "token": "0x4444444444444444444444444444444444444444", "amount": "4000000000000000000", "id": "0x0000000000000000000000000000000000000000000000000000000000000004" },
      { "token": "0x5555555555555555555555555555555555555555", "amount": "5000000000000000000", "id": "0x0000000000000000000000000000000000000000000000000000000000000005" },
      { "token": "0x6666666666666666666666666666666666666666", "amount": "6000000000000000000", "id": "0x0000000000000000000000000000000000000000000000000000000000000006" },
      { "token": "0x7777777777777777777777777777777777777777", "amount": "7000000000000000000", "id": "0x0000000000000000000000000000000000000000000000000000000000000007" },
      { "token": "0x8888888888888888888888888888888888888888", "amount": "8000000000000000000", "id": "0x0000000000000000000000000000000000000000000000000000000000000008" }
    ],
    "metadata": {
      "title": "${LONG_TITLE_X15.replace(/"/g, '\\"')}",
      "description": "${LONG_DESCRIPTION_X15.replace(/"/g, '\\"')}",
      "tags": ["eip712", "order", "signature", "large-payload", "example", "typed-data", "ethereum", "very-long-tags", "production-testing", "wallet-signing", "extended-metadata", "multi-item-order", "deferred-orders", "permit2-style", "gasless-signing"]
    },
    "nonce": "42",
    "expiry": "1735689600",
    "contents": "${LONG_CONTENTS_X15.replace(/"/g, '\\"')}"
  }
}`

// Regression payload for vultisig/vultisig-windows#4731: an automation-order
// style payload where bytes fields hold "" instead of "0x". ethers v6
// TypedDataEncoder rejects "" with `invalid BytesLike value (argument="value",
// value="")` while MetaMask's signer tolerates it — the wallet must reject
// this loudly at request time with an error naming the offending fields.
const EMPTY_BYTES_TYPED_DATA = `{
  "domain": {
    "name": "Automation Order",
    "version": "1",
    "chainId": 8453,
    "verifyingContract": "0x1111111111111111111111111111111111111111"
  },
  "primaryType": "Order",
  "types": {
    "EIP712Domain": [
      { "name": "name", "type": "string" },
      { "name": "version", "type": "string" },
      { "name": "chainId", "type": "uint256" },
      { "name": "verifyingContract", "type": "address" }
    ],
    "Order": [
      { "name": "owner", "type": "address" },
      { "name": "tokenId", "type": "uint256" },
      { "name": "salt", "type": "bytes32" },
      { "name": "extraData", "type": "bytes" }
    ]
  },
  "message": {
    "owner": "0x2222222222222222222222222222222222222222",
    "tokenId": "123456",
    "salt": "",
    "extraData": ""
  }
}`

export { DEFAULT_TYPED_DATA, EMPTY_BYTES_TYPED_DATA }

export function SignTypedDataV4Method({ provider, onResult, onError }: SignTypedDataV4MethodProps) {
  const [address, setAddress] = useState<string>('')
  const [typedDataJson, setTypedDataJson] = useState<string>(DEFAULT_TYPED_DATA)
  const [loading, setLoading] = useState<boolean>(false)

  const handleSign = async (): Promise<void> => {
    const ethProvider = provider as { request?: (args: { method: string; params?: unknown[] }) => Promise<unknown> } | null

    if (!ethProvider) {
      onError('Ethereum provider not available')
      return
    }

    if (!ethProvider.request || typeof ethProvider.request !== 'function') {
      onError('request method is not available')
      return
    }

    const signerAddress = address.trim()
    if (!signerAddress) {
      onError('Signer address is required')
      return
    }

    const trimmedTypedData = typedDataJson.trim()
    if (!trimmedTypedData) {
      onError('Typed data (EIP-712 message) is required')
      return
    }

    setLoading(true)
    try {
      const signature = await ethProvider.request({
        method: 'eth_signTypedData_v4',
        params: [signerAddress, trimmedTypedData],
      })
      onResult({ signature })
    } catch (err) {
      onError((err as Error).message || 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          Signer address <span className="text-red-500">*</span>
        </label>
        <input
          type="text"
          value={address}
          onChange={(e) => setAddress(e.target.value)}
          placeholder="0x..."
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>

      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          EIP-712 typed data (JSON) <span className="text-red-500">*</span>
        </label>
        <textarea
          value={typedDataJson}
          onChange={(e) => setTypedDataJson(e.target.value)}
          placeholder='{"domain":{...},"primaryType":"...","types":{...},"message":{...}}'
          className="w-full px-3 py-2 text-xs font-mono border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y min-h-[320px]"
          rows={20}
          spellCheck={false}
        />
        <p className="text-xs text-gray-500 mt-1">
          Full EIP-712 payload (domain, types, primaryType, message). Supports very large messages.
        </p>
      </div>

      <button
        onClick={handleSign}
        disabled={loading || !address.trim() || !typedDataJson.trim()}
        className="w-full px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Signing...' : 'Sign typed data (eth_signTypedData_v4)'}
      </button>
    </div>
  )
}
