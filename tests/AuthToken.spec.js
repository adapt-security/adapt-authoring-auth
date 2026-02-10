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
  })
})
