import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import Permissions from '../lib/Permissions.js'

describe('Permissions', () => {
  let permissions

  before(async () => {
    permissions = await Permissions.init()
  })

  describe('#secureRoute()', () => {
    it('should secure a route with scopes', () => {
      permissions.secureRoute('/api/users/:id', 'get', ['read:users'])
      const scopes = permissions.getScopesForRoute('get', '/api/users/123')
      assert.deepEqual(scopes, ['read:users'])
    })

    it('should handle multiple scopes', () => {
      permissions.secureRoute('/api/content/:id', 'post', ['write:content', 'create:content'])
      const scopes = permissions.getScopesForRoute('post', '/api/content/456')
      assert.deepEqual(scopes, ['write:content', 'create:content'])
    })

    it('should match routes with path parameters', () => {
      permissions.secureRoute('/api/resources/:resourceId/items/:itemId', 'put', ['write:resources'])
      const scopes = permissions.getScopesForRoute('put', '/api/resources/abc/items/xyz')
      assert.deepEqual(scopes, ['write:resources'])
    })
  })

  describe('#getScopesForRoute()', () => {
    it('should return undefined for unsecured route', () => {
      const scopes = permissions.getScopesForRoute('get', '/api/nonexistent')
      assert.equal(scopes, undefined)
    })

    it('should be case-sensitive for HTTP methods', () => {
      permissions.secureRoute('/api/test', 'delete', ['delete:test'])
      const scopes = permissions.getScopesForRoute('delete', '/api/test')
      assert.deepEqual(scopes, ['delete:test'])
    })

    it('should not match wrong HTTP method', () => {
      permissions.secureRoute('/api/different', 'patch', ['patch:different'])
      const scopes = permissions.getScopesForRoute('get', '/api/different')
      assert.equal(scopes, undefined)
    })

    it('should handle exact path matches', () => {
      permissions.secureRoute('/api/exact/path', 'get', ['read:exact'])
      const scopes = permissions.getScopesForRoute('get', '/api/exact/path')
      assert.deepEqual(scopes, ['read:exact'])
    })
  })
})
