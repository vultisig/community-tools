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
import { PublicKey } from '@solana/web3.js'
import { getTransactionEncoder } from '@solana/transactions'
import { Buffer } from 'buffer'

export type SolanaExampleType = 'transferSOL' | 'transferUSDC' | 'transferSOLLegacy' | 'transferUSDCLegacy'

export const getSolanaExampleDescriptions = (): Record<SolanaExampleType, string> => ({
  transferSOL: 'SOL Transfer (Versioned v0) - Transfer 0.01 SOL',
  transferUSDC: 'USDC Transfer (Versioned v0) - Transfer 0.1 USDC (SPL Token)',
  transferSOLLegacy: 'SOL Transfer (Legacy) - Transfer 0.01 SOL',
  transferUSDCLegacy: 'USDC Transfer (Legacy) - Transfer 0.1 USDC (SPL Token)',
})


/**
 * Build a SOL transfer transaction using @solana/kit
 */
async function buildTransferSOL(
  fromAddress: string,
  toAddress: string,
  amount: number = 0.01
): Promise<string> {
  const SOL_DECIMALS = 9
  const amountLamports = BigInt(Math.floor(amount * Math.pow(10, SOL_DECIMALS)))
  
  const fromAddr = address(fromAddress)
  const toAddr = address(toAddress)
  
  // Use @solana-program/system to create transfer instruction
  // Create a noop signer (doesn't actually sign, just provides the address structure)
  // The actual signing will be done by the wallet when the transaction is signed
  const sourceSigner = createNoopSigner(fromAddr)
  
  const transferInstruction = getTransferSolInstruction({
    source: sourceSigner,
    destination: toAddr,
    amount: amountLamports,
  })

  // Create transaction message using pipe pattern as recommended by Solana Kit docs
  // https://www.solanakit.com/docs/getting-started/build-transaction
  // Get latest blockhash from RPC (using mainnet-beta by default)
  const rpc = createSolanaRpc('https://solana-mainnet.g.alchemy.com/v2/PiMBPAB_R6x92QTdZwt8H6tBvFIGV5SW')
  const { value: latestBlockhash } = await rpc.getLatestBlockhash().send()
  
  const transactionMessage = pipe(
    createTransactionMessage({ version: 0 }),
    (tx) => setTransactionMessageFeePayer(fromAddr, tx),
    (tx) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, tx),
    (tx) => appendTransactionMessageInstruction(transferInstruction, tx),
  )
  
  // Compile transaction - this returns a Transaction object directly
  const transaction = compileTransaction(transactionMessage)
  
  // Serialize to Base64 for display and wallet compatibility
  const transactionEncoder = getTransactionEncoder()
  const transactionBytes = transactionEncoder.encode(transaction)
  const base64String = Buffer.from(transactionBytes).toString('base64')
  
  return base64String
}

/**
 * Build a SOL transfer transaction (Legacy) using @solana/kit
 */
async function buildTransferSOLLegacy(
  fromAddress: string,
  toAddress: string,
  amount: number = 0.01
): Promise<string> {
  const SOL_DECIMALS = 9
  const amountLamports = BigInt(Math.floor(amount * Math.pow(10, SOL_DECIMALS)))
  
  const fromAddr = address(fromAddress)
  const toAddr = address(toAddress)
  
  // Use @solana-program/system to create transfer instruction
  // Create a noop signer (doesn't actually sign, just provides the address structure)
  // The actual signing will be done by the wallet when the transaction is signed
  const sourceSigner = createNoopSigner(fromAddr)
  
  const transferInstruction = getTransferSolInstruction({
    source: sourceSigner,
    destination: toAddr,
    amount: amountLamports,
  })

  // Create transaction message using pipe pattern as recommended by Solana Kit docs
  // https://www.solanakit.com/docs/getting-started/build-transaction
  // Get latest blockhash from RPC (using mainnet-beta by default)
  const rpc = createSolanaRpc('https://solana-mainnet.g.alchemy.com/v2/PiMBPAB_R6x92QTdZwt8H6tBvFIGV5SW')
  const { value: latestBlockhash } = await rpc.getLatestBlockhash().send()
  
  // Legacy transaction: createTransactionMessage({ version: 'legacy' })
  const transactionMessage = pipe(
    createTransactionMessage({ version: 'legacy' }),
    (tx) => setTransactionMessageFeePayer(fromAddr, tx),
    (tx) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, tx),
    (tx) => appendTransactionMessageInstruction(transferInstruction, tx),
  )
  
  // Compile transaction - this returns a Transaction object directly
  const transaction = compileTransaction(transactionMessage)
  
  // Serialize to Base64 for display and wallet compatibility
  const transactionEncoder = getTransactionEncoder()
  const transactionBytes = transactionEncoder.encode(transaction)
  const base64String = Buffer.from(transactionBytes).toString('base64')
  
  return base64String
}

/**
 * Build a USDC (SPL Token) transfer transaction using @solana/kit and @solana/spl-token
 * USDC mint address on Solana: EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
 */
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
  
  // Derive associated token accounts for source and destination
  const sourceTokenAccount = getAssociatedTokenAddressSync(
    mintPublicKey,
    fromPublicKey
  )
  const destinationTokenAccount = getAssociatedTokenAddressSync(
    mintPublicKey,
    toPublicKey
  )
  
  // Create instruction to create associated token account for destination if it doesn't exist
  // This is idempotent - it won't fail if the account already exists
  const createATAInstructionWeb3 = createAssociatedTokenAccountIdempotentInstruction(
    fromPublicKey, // payer
    destinationTokenAccount, // associatedToken
    toPublicKey, // owner
    mintPublicKey // mint
  )
  
  // Convert CreateATA instruction from @solana/web3.js to Instruction from @solana/kit
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
  
  // Create transfer instruction using @solana/spl-token
  const transferInstructionWeb3 = createTransferInstruction(
    sourceTokenAccount,
    destinationTokenAccount,
    fromPublicKey,
    amountSmallestUnit
  )
  
  // Convert Transfer instruction from @solana/web3.js to Instruction from @solana/kit
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

  // Create transaction message using pipe pattern as recommended by Solana Kit docs
  // https://www.solanakit.com/docs/getting-started/build-transaction
  // Get latest blockhash from RPC (using mainnet-beta by default)
  const rpc = createSolanaRpc('https://solana-mainnet.g.alchemy.com/v2/PiMBPAB_R6x92QTdZwt8H6tBvFIGV5SW')
  const { value: latestBlockhash } = await rpc.getLatestBlockhash().send()
  
  // Add both instructions: first create the destination token account, then transfer
  const transactionMessage = pipe(
    createTransactionMessage({ version: 0 }),
    (tx) => setTransactionMessageFeePayer(fromAddr, tx),
    (tx) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, tx),
    (tx) => appendTransactionMessageInstruction(createATAInstruction, tx),
    (tx) => appendTransactionMessageInstruction(transferInstruction, tx),
  )
  
  // Compile transaction - this returns a Transaction object directly
  const transaction = compileTransaction(transactionMessage)
  
  // Serialize to Base64 for display and wallet compatibility
  const transactionEncoder = getTransactionEncoder()
  const transactionBytes = transactionEncoder.encode(transaction)
  const base64String = Buffer.from(transactionBytes).toString('base64')
  
  return base64String
}

/**
 * Build a USDC (SPL Token) transfer transaction (Legacy) using @solana/kit and @solana/spl-token
 * USDC mint address on Solana: EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
 */
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
  
  // Derive associated token accounts for source and destination
  const sourceTokenAccount = getAssociatedTokenAddressSync(
    mintPublicKey,
    fromPublicKey
  )
  const destinationTokenAccount = getAssociatedTokenAddressSync(
    mintPublicKey,
    toPublicKey
  )
  
  // Create instruction to create associated token account for destination if it doesn't exist
  // This is idempotent - it won't fail if the account already exists
  const createATAInstructionWeb3 = createAssociatedTokenAccountIdempotentInstruction(
    fromPublicKey, // payer
    destinationTokenAccount, // associatedToken
    toPublicKey, // owner
    mintPublicKey // mint
  )
  
  // Convert CreateATA instruction from @solana/web3.js to Instruction from @solana/kit
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
  
  // Create transfer instruction using @solana/spl-token
  const transferInstructionWeb3 = createTransferInstruction(
    sourceTokenAccount,
    destinationTokenAccount,
    fromPublicKey,
    amountSmallestUnit
  )
  
  // Convert Transfer instruction from @solana/web3.js to Instruction from @solana/kit
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

  // Create transaction message using pipe pattern as recommended by Solana Kit docs
  // https://www.solanakit.com/docs/getting-started/build-transaction
  // Get latest blockhash from RPC (using mainnet-beta by default)
  const rpc = createSolanaRpc('https://solana-mainnet.g.alchemy.com/v2/PiMBPAB_R6x92QTdZwt8H6tBvFIGV5SW')
  const { value: latestBlockhash } = await rpc.getLatestBlockhash().send()
  
  // Legacy transaction: createTransactionMessage({ version: 'legacy' })
  // Add both instructions: first create the destination token account, then transfer
  const transactionMessage = pipe(
    createTransactionMessage({ version: 'legacy' }),
    (tx) => setTransactionMessageFeePayer(fromAddr, tx),
    (tx) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, tx),
    (tx) => appendTransactionMessageInstruction(createATAInstruction, tx),
    (tx) => appendTransactionMessageInstruction(transferInstruction, tx),
  )
  
  // Compile transaction - this returns a Transaction object directly
  const transaction = compileTransaction(transactionMessage)
  
  // Serialize to Base64 for display and wallet compatibility
  const transactionEncoder = getTransactionEncoder()
  const transactionBytes = transactionEncoder.encode(transaction)
  const base64String = Buffer.from(transactionBytes).toString('base64')
  
  return base64String
}

/**
 * Get example transactions for Solana
 */
export const getSolanaTransactionExamples = async (
  fromAddress: string,
  toAddress: string,
  exampleType: SolanaExampleType
): Promise<string> => {
  if (!fromAddress) {
    throw new Error('From address is required')
  }

  const defaultToAddress = toAddress || '11111111111111111111111111111111' // Placeholder address

  switch (exampleType) {
    case 'transferSOL':
      return await buildTransferSOL(fromAddress, defaultToAddress)
    case 'transferUSDC':
      return await buildTransferUSDC(fromAddress, defaultToAddress)
    case 'transferSOLLegacy':
      return await buildTransferSOLLegacy(fromAddress, defaultToAddress)
    case 'transferUSDCLegacy':
      return await buildTransferUSDCLegacy(fromAddress, defaultToAddress)
    default:
      throw new Error(`Unknown example type: ${exampleType}`)
  }
}

