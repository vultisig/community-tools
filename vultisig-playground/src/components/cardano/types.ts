import type {
  CardanoCip30Extension,
  CardanoCip30FullApi,
  CardanoCip30InitialApi,
  CardanoPaginate,
} from '../../types/vultisig'

export type {
  CardanoCip30Extension,
  CardanoCip30FullApi,
  CardanoCip30InitialApi,
  CardanoPaginate,
}

export interface CardanoCip30ApiError {
  code: number
  info: string
  maxSize?: number
}

export interface MethodComponentProps {
  provider: unknown
  onResult: (result: unknown) => void
  onError: (error: string) => void
  onAccountUpdate?: (accounts: string[]) => void
}
