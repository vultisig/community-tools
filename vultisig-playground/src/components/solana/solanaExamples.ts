import {
  address,
  appendTransactionMessageInstruction,
  createTransactionMessage,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  compileTransaction,
  pipe,
  createNoopSigner,
  createSolanaRpc,
} from '@solana/kit'
import type { Instruction } from '@solana/kit'
import { AccountRole } from '@solana/kit'
import { getTransferSolInstruction } from '@solana-program/system'
import { 
  createTransferInstruction, 
  getAssociatedTokenAddressSync,
  createAssociatedTokenAccountIdempotentInstruction 
} from '@solana/spl-token'
import { PublicKey, Keypair, VersionedTransaction } from '@solana/web3.js'
import { getTransactionEncoder } from '@solana/transactions'
import { Buffer } from 'buffer'

export type SolanaExampleType = 'transferSOL' | 'transferUSDC' | 'transferSOLLegacy' | 'transferUSDCLegacy' | 'partiallySignedSOL'

export const getSolanaExampleDescriptions = (): Record<SolanaExampleType, string> => ({
  transferSOL: 'SOL Transfer (Versioned v0) - Transfer 0.01 SOL',
  transferUSDC: 'USDC Transfer (Versioned v0) - Transfer 0.1 USDC (SPL Token)',
  transferSOLLegacy: 'SOL Transfer (Legacy) - Transfer 0.01 SOL',
  transferUSDCLegacy: 'USDC Transfer (Legacy) - Transfer 0.1 USDC (SPL Token)',
  partiallySignedSOL: 'Partially Signed SOL Transfer (Versioned v0) - Has existing signature',
})

async function buildTransferSOL(
  fromAddress: string,
  toAddress: string,
  amount: number = 0.01
): Promise<string> {
  const SOL_DECIMALS = 9
  const amountLamports = BigInt(Math.floor(amount * Math.pow(10, SOL_DECIMALS)))
  
  const fromAddr = address(fromAddress)
  const toAddr = address(toAddress)
  
  const sourceSigner = createNoopSigner(fromAddr)
  
  const transferInstruction = getTransferSolInstruction({
    source: sourceSigner,
    destination: toAddr,
    amount: amountLamports,
  })

  const rpc = createSolanaRpc('https://solana-mainnet.g.alchemy.com/v2/PiMBPAB_R6x92QTdZwt8H6tBvFIGV5SW')
  const { value: latestBlockhash } = await rpc.getLatestBlockhash().send()
  
  const transactionMessage = pipe(
    createTransactionMessage({ version: 0 }),
    (tx) => setTransactionMessageFeePayer(fromAddr, tx),
    (tx) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, tx),
    (tx) => appendTransactionMessageInstruction(transferInstruction, tx),
  )
  
  const transaction = compileTransaction(transactionMessage)
  
  const transactionEncoder = getTransactionEncoder()
  const transactionBytes = transactionEncoder.encode(transaction)
  const base64String = Buffer.from(transactionBytes).toString('base64')
  
  return base64String
}

async function buildTransferSOLLegacy(
  fromAddress: string,
  toAddress: string,
  amount: number = 0.01
): Promise<string> {
  const SOL_DECIMALS = 9
  const amountLamports = BigInt(Math.floor(amount * Math.pow(10, SOL_DECIMALS)))
  
  const fromAddr = address(fromAddress)
  const toAddr = address(toAddress)
  
  const sourceSigner = createNoopSigner(fromAddr)
  
  const transferInstruction = getTransferSolInstruction({
    source: sourceSigner,
    destination: toAddr,
    amount: amountLamports,
  })

  const rpc = createSolanaRpc('https://solana-mainnet.g.alchemy.com/v2/PiMBPAB_R6x92QTdZwt8H6tBvFIGV5SW')
  const { value: latestBlockhash } = await rpc.getLatestBlockhash().send()
  
  const transactionMessage = pipe(
    createTransactionMessage({ version: 'legacy' }),
    (tx) => setTransactionMessageFeePayer(fromAddr, tx),
    (tx) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, tx),
    (tx) => appendTransactionMessageInstruction(transferInstruction, tx),
  )
  
  const transaction = compileTransaction(transactionMessage)
  
  const transactionEncoder = getTransactionEncoder()
  const transactionBytes = transactionEncoder.encode(transaction)
  const base64String = Buffer.from(transactionBytes).toString('base64')
  
  return base64String
}

async function buildTransferUSDC(
  fromAddress: string,
  toAddress: string,
  amount: number = 0.1
): Promise<string> {
  const USDC_DECIMALS = 6
  const USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
  const amountSmallestUnit = BigInt(Math.floor(amount * Math.pow(10, USDC_DECIMALS)))
  
  const fromAddr = address(fromAddress)
  const mintPublicKey = new PublicKey(USDC_MINT)
  const fromPublicKey = new PublicKey(fromAddress)
  const toPublicKey = new PublicKey(toAddress)
  
  const sourceTokenAccount = getAssociatedTokenAddressSync(
    mintPublicKey,
    fromPublicKey
  )
  const destinationTokenAccount = getAssociatedTokenAddressSync(
    mintPublicKey,
    toPublicKey
  )
  
  const createATAInstructionWeb3 = createAssociatedTokenAccountIdempotentInstruction(
    fromPublicKey,
    destinationTokenAccount,
    toPublicKey,
    mintPublicKey
  )
  
  const createATAInstruction: Instruction = {
    programAddress: address(createATAInstructionWeb3.programId.toBase58()),
    accounts: createATAInstructionWeb3.keys.map((key) => ({
      address: address(key.pubkey.toBase58()),
      role: key.isWritable
        ? (key.isSigner ? AccountRole.WRITABLE_SIGNER : AccountRole.WRITABLE)
        : (key.isSigner ? AccountRole.READONLY_SIGNER : AccountRole.READONLY),
    })),
    data: new Uint8Array(createATAInstructionWeb3.data),
  }
  
  const transferInstructionWeb3 = createTransferInstruction(
    sourceTokenAccount,
    destinationTokenAccount,
    fromPublicKey,
    amountSmallestUnit
  )
  
  const transferInstruction: Instruction = {
    programAddress: address(transferInstructionWeb3.programId.toBase58()),
    accounts: transferInstructionWeb3.keys.map((key) => ({
      address: address(key.pubkey.toBase58()),
      role: key.isWritable
        ? (key.isSigner ? AccountRole.WRITABLE_SIGNER : AccountRole.WRITABLE)
        : (key.isSigner ? AccountRole.READONLY_SIGNER : AccountRole.READONLY),
    })),
    data: new Uint8Array(transferInstructionWeb3.data),
  }

  const rpc = createSolanaRpc('https://solana-mainnet.g.alchemy.com/v2/PiMBPAB_R6x92QTdZwt8H6tBvFIGV5SW')
  const { value: latestBlockhash } = await rpc.getLatestBlockhash().send()
  
  const transactionMessage = pipe(
    createTransactionMessage({ version: 0 }),
    (tx) => setTransactionMessageFeePayer(fromAddr, tx),
    (tx) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, tx),
    (tx) => appendTransactionMessageInstruction(createATAInstruction, tx),
    (tx) => appendTransactionMessageInstruction(transferInstruction, tx),
  )
  
  const transaction = compileTransaction(transactionMessage)
  
  const transactionEncoder = getTransactionEncoder()
  const transactionBytes = transactionEncoder.encode(transaction)
  const base64String = Buffer.from(transactionBytes).toString('base64')
  
  return base64String
}

async function buildTransferUSDCLegacy(
  fromAddress: string,
  toAddress: string,
  amount: number = 0.1
): Promise<string> {
  const USDC_DECIMALS = 6
  const USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
  const amountSmallestUnit = BigInt(Math.floor(amount * Math.pow(10, USDC_DECIMALS)))
  
  const fromAddr = address(fromAddress)
  const mintPublicKey = new PublicKey(USDC_MINT)
  const fromPublicKey = new PublicKey(fromAddress)
  const toPublicKey = new PublicKey(toAddress)
  
  const sourceTokenAccount = getAssociatedTokenAddressSync(
    mintPublicKey,
    fromPublicKey
  )
  const destinationTokenAccount = getAssociatedTokenAddressSync(
    mintPublicKey,
    toPublicKey
  )
  
  const createATAInstructionWeb3 = createAssociatedTokenAccountIdempotentInstruction(
    fromPublicKey,
    destinationTokenAccount,
    toPublicKey,
    mintPublicKey
  )
  
  const createATAInstruction: Instruction = {
    programAddress: address(createATAInstructionWeb3.programId.toBase58()),
    accounts: createATAInstructionWeb3.keys.map((key) => ({
      address: address(key.pubkey.toBase58()),
      role: key.isWritable
        ? (key.isSigner ? AccountRole.WRITABLE_SIGNER : AccountRole.WRITABLE)
        : (key.isSigner ? AccountRole.READONLY_SIGNER : AccountRole.READONLY),
    })),
    data: new Uint8Array(createATAInstructionWeb3.data),
  }
  
  const transferInstructionWeb3 = createTransferInstruction(
    sourceTokenAccount,
    destinationTokenAccount,
    fromPublicKey,
    amountSmallestUnit
  )
  
  const transferInstruction: Instruction = {
    programAddress: address(transferInstructionWeb3.programId.toBase58()),
    accounts: transferInstructionWeb3.keys.map((key) => ({
      address: address(key.pubkey.toBase58()),
      role: key.isWritable
        ? (key.isSigner ? AccountRole.WRITABLE_SIGNER : AccountRole.WRITABLE)
        : (key.isSigner ? AccountRole.READONLY_SIGNER : AccountRole.READONLY),
    })),
    data: new Uint8Array(transferInstructionWeb3.data),
  }

  const rpc = createSolanaRpc('https://solana-mainnet.g.alchemy.com/v2/PiMBPAB_R6x92QTdZwt8H6tBvFIGV5SW')
  const { value: latestBlockhash } = await rpc.getLatestBlockhash().send()
  
  const transactionMessage = pipe(
    createTransactionMessage({ version: 'legacy' }),
    (tx) => setTransactionMessageFeePayer(fromAddr, tx),
    (tx) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, tx),
    (tx) => appendTransactionMessageInstruction(createATAInstruction, tx),
    (tx) => appendTransactionMessageInstruction(transferInstruction, tx),
  )
  
  const transaction = compileTransaction(transactionMessage)
  
  const transactionEncoder = getTransactionEncoder()
  const transactionBytes = transactionEncoder.encode(transaction)
  const base64String = Buffer.from(transactionBytes).toString('base64')
  
  return base64String
}

export interface PartiallySignedTransactionResult {
  transaction: string
  partialSignerPublicKey: string
}

async function buildPartiallySignedSOL(
  fromAddress: string,
  toAddress: string,
  amount: number = 0.01
): Promise<PartiallySignedTransactionResult> {
  const SOL_DECIMALS = 9
  const amountLamports = BigInt(Math.floor(amount * Math.pow(10, SOL_DECIMALS)))
  
  const fromAddr = address(fromAddress)
  const toAddr = address(toAddress)
  
  const sourceSigner = createNoopSigner(fromAddr)
  
  const transferInstruction = getTransferSolInstruction({
    source: sourceSigner,
    destination: toAddr,
    amount: amountLamports,
  })

  const rpc = createSolanaRpc('https://solana-mainnet.g.alchemy.com/v2/PiMBPAB_R6x92QTdZwt8H6tBvFIGV5SW')
  const { value: latestBlockhash } = await rpc.getLatestBlockhash().send()
  
  const testKeypair = Keypair.generate()
  const testPublicKey = testKeypair.publicKey
  const testAddr = address(testPublicKey.toBase58())
  
  const testSourceSigner = createNoopSigner(testAddr)
  const testTransferInstruction = getTransferSolInstruction({
    source: testSourceSigner,
    destination: toAddr,
    amount: BigInt(0),
  })
  
  const transactionMessageWithTestSigner = pipe(
    createTransactionMessage({ version: 0 }),
    (tx) => setTransactionMessageFeePayer(fromAddr, tx),
    (tx) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, tx),
    (tx) => appendTransactionMessageInstruction(transferInstruction, tx),
    (tx) => appendTransactionMessageInstruction(testTransferInstruction, tx),
  )
  
  const transactionWithTestSigner = compileTransaction(transactionMessageWithTestSigner)
  
  const transactionEncoder = getTransactionEncoder()
  const transactionBytesReadonly = transactionEncoder.encode(transactionWithTestSigner)
  const transactionBytesWithTestSigner = new Uint8Array(transactionBytesReadonly)
  
  const versionedTransaction = VersionedTransaction.deserialize(transactionBytesWithTestSigner)
  
  versionedTransaction.sign([testKeypair])
  
  const partiallySignedBytes = versionedTransaction.serialize()
  const base64String = Buffer.from(partiallySignedBytes).toString('base64')
  
  return {
    transaction: base64String,
    partialSignerPublicKey: testPublicKey.toBase58(),
  }
}

export const getSolanaTransactionExamples = async (
  fromAddress: string,
  toAddress: string,
  exampleType: SolanaExampleType
): Promise<string | PartiallySignedTransactionResult> => {
  if (!fromAddress) {
    throw new Error('From address is required')
  }

  const defaultToAddress = toAddress || '11111111111111111111111111111111'

  switch (exampleType) {
    case 'transferSOL':
      return await buildTransferSOL(fromAddress, defaultToAddress)
    case 'transferUSDC':
      return await buildTransferUSDC(fromAddress, defaultToAddress)
    case 'transferSOLLegacy':
      return await buildTransferSOLLegacy(fromAddress, defaultToAddress)
    case 'transferUSDCLegacy':
      return await buildTransferUSDCLegacy(fromAddress, defaultToAddress)
    case 'partiallySignedSOL':
      return await buildPartiallySignedSOL(fromAddress, defaultToAddress)
    default:
      throw new Error(`Unknown example type: ${exampleType}`)
  }
}

