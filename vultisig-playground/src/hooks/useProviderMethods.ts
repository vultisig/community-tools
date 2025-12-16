import { useState, useEffect } from 'react'

export function useProviderMethods(providerName: string) {
  const [methods, setMethods] = useState<string[]>([])

  useEffect(() => {
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

    setMethods(methodNames.sort())
  }, [providerName])

  return methods
}
