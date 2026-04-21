import { useState, useEffect } from 'react'
import { tronMethodMapping } from '../components/tron/methodMapping'
import { tonMethodMapping } from '../components/ton/methodMapping'
import { cardanoMethodMapping } from '../components/cardano/methodMapping'

export function useProviderMethods(providerName: string) {
  const [methods, setMethods] = useState<string[]>([])

  useEffect(() => {
    if (providerName === 'polkadot') {
      if (window.injectedWeb3?.['polkadot-js']) {
        setMethods(['injectedWeb3'])
      } else {
        setMethods([])
      }
      return
    }

    if (providerName === 'ton') {
      const tonProvider = window.vultisig?.ton as { tonconnect?: unknown } | undefined
      if (tonProvider?.tonconnect) {
        setMethods(Object.keys(tonMethodMapping))
      } else {
        setMethods([])
      }
      return
    }

    if (providerName === 'cardano') {
      if (window.cardano?.vultisig) {
        setMethods(Object.keys(cardanoMethodMapping))
      } else {
        setMethods([])
      }
      return
    }

    if (!window.vultisig) {
      setMethods([])
      return
    }

    const providerInstance = (window.vultisig as Record<string, unknown>)[providerName]

    if (!providerInstance) {
      setMethods([])
      return
    }

    const methodNames: string[] = []
    const providerObj = providerInstance as Record<string, unknown>
    
    const ownPropertyNames = Object.getOwnPropertyNames(providerObj)
    
    for (const key of ownPropertyNames) {
      const value = providerObj[key]
      if (typeof value === 'function') {
        methodNames.push(key)
      }
    }

    const prototype = Object.getPrototypeOf(providerObj)
    if (prototype && prototype !== Object.prototype) {
      const prototypePropertyNames = Object.getOwnPropertyNames(prototype)
      
      for (const key of prototypePropertyNames) {
        if (key === 'constructor') continue
        const descriptor = Object.getOwnPropertyDescriptor(prototype, key)
        if (descriptor) {
          if (descriptor.value && typeof descriptor.value === 'function') {
            if (!methodNames.includes(key)) {
              methodNames.push(key)
            }
          } else if (descriptor.get && typeof descriptor.get === 'function') {
            if (!methodNames.includes(key)) {
              methodNames.push(key)
            }
          }
        }
      }
    }

    if (providerName === 'tron') {
      const tronMethods = Object.keys(tronMethodMapping)
      for (const method of tronMethods) {
        if (!methodNames.includes(method)) {
          methodNames.push(method)
        }
      }
    }

    setMethods(methodNames.sort())
  }, [providerName])

  return methods
}
