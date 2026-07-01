import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { resolveTokenScopes } from '../lib/utils/resolveTokenScopes.js'

/**
 * Fake error registry: each entry is a throwable carrying its code, with a
 * chainable setData() mirroring App.instance.errors — so the pure util can be
 * tested without App.instance.
 */
function makeErrors () {
  const mk = code => {
    const e = new Error(code)
    e.code = code
    e.setData = function (data) { this.data = data; return this }
    return e
  }
  return {
    SUPER_TOKEN_FORBIDDEN: mk('SUPER_TOKEN_FORBIDDEN'),
    INVALID_PARAMS: mk('INVALID_PARAMS'),
    TOKEN_SCOPE_INVALID: mk('TOKEN_SCOPE_INVALID')
  }
}

const byCode = code => err => err.code === code

describe('resolveTokenScopes()', () => {
  const errors = makeErrors()

  describe('login / inherited-scope tokens (no requestedScopes)', () => {
    it('returns undefined for a normal user (inherit full scopes)', () => {
      const result = resolveTokenScopes({ authType: 'local', userScopes: ['read:content', 'write:content'] }, errors)
      assert.equal(result, undefined)
    })

    it('returns undefined for a super user logging in (super may hold a session token)', () => {
      const result = resolveTokenScopes({ authType: 'local', userScopes: ['*:*'] }, errors)
      assert.equal(result, undefined)
    })

    it('returns undefined for a non-super manual token (self-service token still works)', () => {
      const result = resolveTokenScopes({ authType: 'manual', userScopes: ['read:content'] }, errors)
      assert.equal(result, undefined)
    })
  })

  describe('super-admin manual token block', () => {
    it('throws SUPER_TOKEN_FORBIDDEN when a super user mints a manual token', () => {
      assert.throws(
        () => resolveTokenScopes({ authType: 'manual', userScopes: ['*:*'] }, errors),
        byCode('SUPER_TOKEN_FORBIDDEN')
      )
    })

    it('a user with *:* plus other scopes is not super, so may mint a manual token', () => {
      const result = resolveTokenScopes({ authType: 'manual', userScopes: ['*:*', 'read:content'] }, errors)
      assert.equal(result, undefined)
    })
  })

  describe('scoped tokens', () => {
    it('returns the requested scopes when they are a subset of the user\'s', () => {
      const result = resolveTokenScopes(
        { authType: 'blueprint', userScopes: ['read:content', 'write:content', 'read:users'], requestedScopes: ['read:content', 'write:content'] },
        errors
      )
      assert.deepEqual(result, ['read:content', 'write:content'])
    })

    it('lets a super user request any concrete scopes (super holds all)', () => {
      const result = resolveTokenScopes(
        { authType: 'blueprint', userScopes: ['*:*'], requestedScopes: ['read:content', 'write:content'] },
        errors
      )
      assert.deepEqual(result, ['read:content', 'write:content'])
    })

    it('throws TOKEN_SCOPE_INVALID when a non-super requests scopes it lacks', () => {
      assert.throws(
        () => resolveTokenScopes(
          { authType: 'blueprint', userScopes: ['read:content'], requestedScopes: ['read:content', 'write:users'] },
          errors
        ),
        err => {
          assert.equal(err.code, 'TOKEN_SCOPE_INVALID')
          assert.deepEqual(err.data, { scopes: ['write:users'] })
          return true
        }
      )
    })

    it('never lets a scoped token carry the super wildcard, even for a super user', () => {
      assert.throws(
        () => resolveTokenScopes({ authType: 'blueprint', userScopes: ['*:*'], requestedScopes: ['*:*'] }, errors),
        byCode('SUPER_TOKEN_FORBIDDEN')
      )
    })

    it('throws INVALID_PARAMS when requestedScopes is not an array', () => {
      assert.throws(
        () => resolveTokenScopes({ authType: 'blueprint', userScopes: ['read:content'], requestedScopes: 'read:content' }, errors),
        byCode('INVALID_PARAMS')
      )
    })

    it('returns an empty array unchanged (an explicitly no-access token)', () => {
      const result = resolveTokenScopes({ authType: 'blueprint', userScopes: ['read:content'], requestedScopes: [] }, errors)
      assert.deepEqual(result, [])
    })
  })
})
