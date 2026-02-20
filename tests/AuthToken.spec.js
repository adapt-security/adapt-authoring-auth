import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import AuthToken from '../lib/AuthToken.js'

describe('AuthToken', () => {
  describe('#getSignature()', () => {
    it('should extract signature from JWT token', () => {
      const token = 'header.payload.signature'
      const signature = AuthToken.getSignature(token)
      assert.equal(signature, 'signature')
    })

    it('should return undefined for malformed token', () => {
      const token = 'invalid'
      const signature = AuthToken.getSignature(token)
      assert.equal(signature, undefined)
    })

    it('should extract third part from token with more than three parts', () => {
      const token = 'header.payload.signature.extra'
      const signature = AuthToken.getSignature(token)
      assert.equal(signature, 'signature')
    })

    it('should handle empty token parts', () => {
      const token = '..'
      const signature = AuthToken.getSignature(token)
      assert.equal(signature, '')
    })

    it('should handle token with only two parts', () => {
      const token = 'header.payload'
      const signature = AuthToken.getSignature(token)
      assert.equal(signature, undefined)
    })

    it('should handle realistic JWT signature', () => {
      const token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc123def456'
      const signature = AuthToken.getSignature(token)
      assert.equal(signature, 'abc123def456')
    })

    it('should return empty string for token ending with dot', () => {
      const token = 'header.payload.'
      const signature = AuthToken.getSignature(token)
      assert.equal(signature, '')
    })

    it('should handle signature with special characters', () => {
      const token = 'a.b.abc-def_ghi+jkl/mno='
      const signature = AuthToken.getSignature(token)
      assert.equal(signature, 'abc-def_ghi+jkl/mno=')
    })

    it('should handle empty string', () => {
      const signature = AuthToken.getSignature('')
      assert.equal(signature, undefined)
    })
  })

  describe('#isSuper()', () => {
    it('should return true for super user scope', () => {
      const scopes = ['*:*']
      assert.equal(AuthToken.isSuper(scopes), true)
    })

    it('should return false for empty scopes', () => {
      const scopes = []
      assert.equal(AuthToken.isSuper(scopes), false)
    })

    it('should return false for regular scopes', () => {
      const scopes = ['read:users', 'write:content']
      assert.equal(AuthToken.isSuper(scopes), false)
    })

    it('should return false when super scope is not the only scope', () => {
      const scopes = ['*:*', 'read:users']
      assert.equal(AuthToken.isSuper(scopes), false)
    })

    it('should return false for similar but not exact super scope', () => {
      const scopes = ['*:']
      assert.equal(AuthToken.isSuper(scopes), false)
    })

    it('should return false for partial wildcard scopes', () => {
      assert.equal(AuthToken.isSuper(['*:users']), false)
      assert.equal(AuthToken.isSuper(['read:*']), false)
    })

    it('should return false for single non-super scope', () => {
      assert.equal(AuthToken.isSuper(['admin:all']), false)
    })
  })

  describe('.secret', () => {
    it('should be a static getter', () => {
      const descriptor = Object.getOwnPropertyDescriptor(AuthToken, 'secret')
      assert.equal(typeof descriptor.get, 'function')
    })
  })

  describe('.generate()', () => {
    it('should be a static method', () => {
      assert.equal(typeof AuthToken.generate, 'function')
    })
  })

  describe('.decode()', () => {
    it('should be a static method', () => {
      assert.equal(typeof AuthToken.decode, 'function')
    })
  })

  describe('.find()', () => {
    it('should be a static method', () => {
      assert.equal(typeof AuthToken.find, 'function')
    })
  })

  describe('.revoke()', () => {
    it('should be a static method', () => {
      assert.equal(typeof AuthToken.revoke, 'function')
    })
  })

  describe('.initRequestData()', () => {
    it('should be a static method', () => {
      assert.equal(typeof AuthToken.initRequestData, 'function')
    })
  })

  // TODO: Bug - initRequestData accesses user.authType before checking if user exists
  // In AuthToken.js lines 43-45:
  //   const [user] = await users.find({ email: token.sub })
  //   const authPlugin = auth.authentication.plugins[user.authType]
  //   if (!user) { throw ... }
  // If users.find returns an empty array, user is undefined, and accessing
  // user.authType throws TypeError before the UNAUTHENTICATED error check
  // The authPlugin lookup should be moved after the user existence check.

  // TODO: Bug - decode() does not handle unknown JWT error names
  // In AuthToken.js lines 113-123, the switch only handles three known error
  // names (JsonWebTokenError, NotBeforeError, TokenExpiredError). If an
  // unknown error name is thrown by jwt.verify, the switch falls through
  // without throwing, then tries to revoke(tokenData) where tokenData is
  // still undefined, and then tries to access tokenData.sub on line 125,
  // causing a TypeError instead of a meaningful error.
})
