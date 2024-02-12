/*
 * @adonisjs/hash
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { Hash } from '../src/hash'
import { Argon } from '../src/drivers/argon'
import { Bcrypt } from '../src/drivers/bcrypt'
import { Scrypt } from '../src/drivers/scrypt'
import { HashManager } from '../src/hash_manager'

test.group('Hash manager', () => {
  test('create hash instance from the manager', ({ assert, expectTypeOf }) => {
    const manager = new HashManager({
      default: 'argon',
      list: {
        argon: () => new Argon({}),
        bcrypt: () => new Bcrypt({}),
        scrypt: () => new Scrypt({}),
      },
    })

    expectTypeOf(manager.use)
      .parameter(0)
      .toEqualTypeOf<'argon' | 'scrypt' | 'bcrypt' | undefined>()

    expectTypeOf(manager.use('argon')).toEqualTypeOf<Hash>()
    expectTypeOf(manager.use('bcrypt')).toEqualTypeOf<Hash>()
    expectTypeOf(manager.use('scrypt')).toEqualTypeOf<Hash>()

    assert.instanceOf(manager.use('argon'), Hash)
    assert.instanceOf(manager.use('bcrypt'), Hash)
    assert.instanceOf(manager.use('scrypt'), Hash)
  })

  test('cache hash instance', ({ assert, expectTypeOf }) => {
    const manager = new HashManager({
      default: 'argon',
      list: {
        argon: () => new Argon({}),
        argon1: () => new Argon({}),
        bcrypt: () => new Bcrypt({}),
        bcrypt1: () => new Bcrypt({}),
        scrypt: () => new Scrypt({}),
        scrypt1: () => new Scrypt({}),
      },
    })

    expectTypeOf(manager.use)
      .parameter(0)
      .toEqualTypeOf<'argon' | 'argon1' | 'scrypt' | 'scrypt1' | 'bcrypt' | 'bcrypt1' | undefined>()

    expectTypeOf(manager.use('argon')).toEqualTypeOf<Hash>()
    expectTypeOf(manager.use('bcrypt')).toEqualTypeOf<Hash>()
    expectTypeOf(manager.use('scrypt')).toEqualTypeOf<Hash>()
    expectTypeOf(manager.use('argon1')).toEqualTypeOf<Hash>()
    expectTypeOf(manager.use('bcrypt1')).toEqualTypeOf<Hash>()
    expectTypeOf(manager.use('scrypt1')).toEqualTypeOf<Hash>()

    assert.strictEqual(manager.use('argon'), manager.use('argon'))
    assert.notStrictEqual(manager.use('argon'), manager.use('argon1'))

    assert.strictEqual(manager.use('bcrypt'), manager.use('bcrypt'))
    assert.notStrictEqual(manager.use('bcrypt'), manager.use('bcrypt1'))

    assert.strictEqual(manager.use('scrypt'), manager.use('scrypt'))
    assert.notStrictEqual(manager.use('scrypt'), manager.use('scrypt1'))
  })

  test('use default hasher', ({ assert }) => {
    const manager = new HashManager({
      default: 'argon',
      list: {
        argon: () => new Argon({}),
        bcrypt: () => new Bcrypt({}),
        scrypt: () => new Scrypt({}),
      },
    })

    assert.strictEqual(manager.use(), manager.use('argon'))
    assert.notStrictEqual(manager.use(), manager.use('bcrypt'))
    assert.notStrictEqual(manager.use(), manager.use('scrypt'))
  })

  test('fail when default hasher is not configured', ({ assert }) => {
    const manager = new HashManager({
      list: {
        argon: () => new Argon({}),
        bcrypt: () => new Bcrypt({}),
        scrypt: () => new Scrypt({}),
      },
    })

    assert.throws(
      () => manager.use(),
      'Cannot create hash instance. No default hasher is defined in the config'
    )
  })

  test('fake all hashers', async ({ assert }) => {
    const manager = new HashManager({
      default: 'argon',
      list: {
        argon: () => new Argon({}),
        bcrypt: () => new Bcrypt({}),
        scrypt: () => new Scrypt({}),
      },
    })

    manager.fake()
    assert.equal(await manager.use('argon').make('hello-world'), 'hello-world')
    assert.equal(await manager.use('bcrypt').make('hello-world'), 'hello-world')
    assert.equal(await manager.use('scrypt').make('hello-world'), 'hello-world')

    manager.restore()
    assert.notEqual(await manager.use('argon').make('hello-world'), 'hello-world')
    assert.notEqual(await manager.use('bcrypt').make('hello-world'), 'hello-world')
    assert.notEqual(await manager.use('scrypt').make('hello-world'), 'hello-world')
  })

  test('hash text using the default driver', async ({ assert }) => {
    const manager = new HashManager({
      default: 'argon',
      list: {
        argon: () => new Argon({}),
      },
    })

    const hashedValue = await manager.make('secret')
    assert.isTrue(manager.isValidHash(hashedValue))
  })

  test('verify hash using the default driver', async ({ assert }) => {
    const manager = new HashManager({
      default: 'argon',
      list: {
        argon: () => new Argon({}),
      },
    })

    const hashedValue = await manager.make('secret')
    assert.isTrue(await manager.verify(hashedValue, 'secret'))
  })

  test('check if hash needs to be rehashed using the default driver', async ({ assert }) => {
    const manager = new HashManager({
      default: 'argon',
      list: {
        argon: () => new Argon({}),
      },
    })

    const hashedValue = await manager.make('secret')
    assert.isFalse(manager.needsReHash(hashedValue))
  })

  test('assert hashed value against plain value', async ({ assert }) => {
    const manager = new HashManager({
      default: 'argon',
      list: {
        argon: () => new Argon({}),
      },
    })

    const hashedValue = await manager.make('secret')
    await assert.doesNotRejects(() => manager.assertEquals(hashedValue, 'secret'))
    await assert.rejects(
      () => manager.assertEquals(hashedValue, 'seret'),
      'Expected "seret" to pass hash verification'
    )

    await assert.doesNotRejects(() => manager.assertNotEquals(hashedValue, 'seret'))
    await assert.rejects(
      () => manager.assertNotEquals(hashedValue, 'secret'),
      'Expected "secret" to fail hash verification'
    )
  })
})
