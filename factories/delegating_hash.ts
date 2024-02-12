import { HashDriverContract } from '../src/types'
import { PhcFormatter } from '../src/phc_formatter'
import { Bcrypt } from '../src/drivers/bcrypt'
import { Scrypt } from '../src/drivers/scrypt'
import { Argon } from '../src/drivers/argon'

export default class DelegatingHashDriver implements HashDriverContract {
  private readonly idForMake: string
  private readonly hashDriverForMake: HashDriverContract
  private readonly idToHashDriver: Map<string, HashDriverContract>
  private defaultHashDriverForVerify: HashDriverContract
  private readonly phcFormatter = new PhcFormatter<{
    t: number
    m: number
    p: number
  }>()

  static createInstance() {
    const map = new Map<string, HashDriverContract>()
    map.set(
      'argon2id',
      new Argon({
        variant: 'id',
      })
    )
    map.set('bcrypt', new Bcrypt({}))
    map.set('scrypt', new Scrypt({}))
    return new DelegatingHashDriver('bcrypt', map)
  }

  constructor(idForMake: string, idToHashDriver: Map<string, HashDriverContract>) {
    if (!idForMake) {
      throw new Error('idForMake cannot be null')
    }

    if (!idToHashDriver.has(idForMake)) {
      throw new Error(`idForMake ${idForMake} is not found in idToHashDriver`)
    }

    this.idForMake = idForMake
    this.hashDriverForMake = idToHashDriver.get(idForMake)!
    this.idToHashDriver = new Map(idToHashDriver)
    this.defaultHashDriverForVerify = new UnmappedIdHashDriver()
  }

  setDefaultHashDriverForVerify(defaultHashDriverForVerify: HashDriverContract): void {
    if (!defaultHashDriverForVerify) {
      throw new Error('defaultHashDriverForVerify cannot be null')
    }
    this.defaultHashDriverForVerify = defaultHashDriverForVerify
  }

  async make(value: string): Promise<string>
  async make(value: string, idForMake: string): Promise<string>
  async make(value: string, idForMake?: string): Promise<string> {
    if (idForMake) {
      const delegate = this.idToHashDriver.get(idForMake)
      if (!delegate) {
        throw new Error(`There is no HashDriver mapped for the id "${idForMake}"`)
      }
      return await delegate.make(value)
    }
    return await this.hashDriverForMake.make(value)
  }

  async verify(hashedValue: string, plainValue: string): Promise<boolean> {
    if (!hashedValue && !plainValue) {
      return true
    }
    const id = this.extractId(hashedValue)
    const delegate = this.idToHashDriver.get(id)
    if (!delegate) {
      return this.defaultHashDriverForVerify.verify(hashedValue, plainValue)
    }
    return await delegate.verify(hashedValue, plainValue)
  }

  isValidHash(value: string): boolean {
    const id = this.extractId(value)
    const delegate = this.idToHashDriver.get(id)
    if (!delegate) {
      return this.defaultHashDriverForVerify.isValidHash(value)
    }
    return delegate.isValidHash(value)
  }

  needsReHash(hashedValue: string): boolean {
    const id = this.extractId(hashedValue)
    if (this.idForMake.toLowerCase() !== id?.toLowerCase()) {
      return true
    } else {
      return this.idToHashDriver.get(id!)!.needsReHash(hashedValue)
    }
  }

  private extractId(hashedValue: string): string {
    const phcNode = this.phcFormatter.deserialize(hashedValue)
    return phcNode.id
  }
}

class UnmappedIdHashDriver implements HashDriverContract {
  private readonly phcFormatter = new PhcFormatter<{
    t: number
    m: number
    p: number
  }>()

  async make(_value: string): Promise<never> {
    throw new Error('make is not supported')
  }

  async verify(hashedValue: string, _plainValue: string): Promise<never> {
    const id = this.extractId(hashedValue)
    throw new Error(`There is no HashDriver mapped for the id "${id}"`)
  }

  isValidHash(_value: string): never {
    throw new Error('isValidHash is not supported')
  }

  needsReHash(_hashedValue: string): never {
    throw new Error('needsReHash is not supported')
  }

  private extractId(hashedValue: string): string {
    const phcNode = this.phcFormatter.deserialize(hashedValue)
    return phcNode.id
  }
}

// Example usage:

// const idForMake = "bcrypt";
// const hashDrivers = new Map<string, HashDriverContract>([
//   [idForMake, new BCryptHashDriver()],
//   // Add other hash drivers here
// ]);
//
// const hashDriver = new DelegatingHashDriver(idForMake, hashDrivers);

// Now you can use hashDriver.make(), hashDriver.verify(), hashDriver.isValidHash(), and hashDriver.needsReHash() just like in Java
