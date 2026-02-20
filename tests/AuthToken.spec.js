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
})
