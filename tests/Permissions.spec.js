import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { App } from 'adapt-authoring-core'
import Permissions from '../lib/Permissions.js'

function mockAppInstance (mockApp) {
  Object.defineProperty(App, 'instance', {
    get: () => mockApp,
    configurable: true
  })
}

function restoreAppInstance () {
  delete App.instance
}

describe('Permissions', () => {
  let permissions

  before(async () => {
    mockAppInstance({
      onReady: () => Promise.resolve({
        waitForModule: async () => [
          { getConfig: () => false }, // auth with logMissingPermissions=false
          { api: { flattenRouters: () => [] } } // server
        ]
      })
    })
    permissions = await Permissions.init()
  })

  after(() => {
    restoreAppInstance()
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

    it('should normalize HTTP method to lowercase', () => {
      permissions.secureRoute('/api/admin', 'DELETE', ['delete:admin'])
      const scopes = permissions.getScopesForRoute('delete', '/api/admin')
      assert.deepEqual(scopes, ['delete:admin'])
    })

    it('should store routes as regexp/scopes pairs', () => {
      const initialLength = permissions.routes.patch.length
      permissions.secureRoute('/api/items/:id', 'patch', ['update:items'])
      assert.equal(permissions.routes.patch.length, initialLength + 1)
      const entry = permissions.routes.patch[permissions.routes.patch.length - 1]
      assert.ok(Array.isArray(entry))
      assert.equal(entry.length, 2)
      assert.ok(entry[0] instanceof RegExp)
      assert.deepEqual(entry[1], ['update:items'])
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

    it('should not match partial path', () => {
      permissions.secureRoute('/api/full', 'get', ['read:full'])
      const scopes = permissions.getScopesForRoute('get', '/api/full/extra')
      assert.equal(scopes, undefined)
    })
  })

  describe('#check()', () => {
    it('should allow super users regardless of scopes', async () => {
      permissions.secureRoute('/api/restricted', 'get', ['admin:all'])

      const req = {
        baseUrl: '/api',
        path: '/restricted',
        method: 'get',
        auth: { isSuper: true, scopes: ['*:*'] }
      }

      await assert.doesNotReject(() => permissions.check(req))
    })

    it('should allow users with matching scopes', async () => {
      permissions.secureRoute('/api/data', 'get', ['read:data'])

      const req = {
        baseUrl: '/api',
        path: '/data',
        method: 'get',
        auth: { isSuper: false, scopes: ['read:data', 'write:data'] }
      }

      await assert.doesNotReject(() => permissions.check(req))
    })

    it('should strip trailing slash from path', async () => {
      permissions.secureRoute('/api/trailing', 'get', ['read:trailing'])

      const req = {
        baseUrl: '/api',
        path: '/trailing/',
        method: 'get',
        auth: { isSuper: false, scopes: ['read:trailing'] }
      }

      await assert.doesNotReject(() => permissions.check(req))
    })
  })

  describe('constructor', () => {
    it('should initialize routes as empty store', () => {
      assert.ok(Array.isArray(permissions.routes.get))
      assert.ok(Array.isArray(permissions.routes.post))
      assert.ok(Array.isArray(permissions.routes.put))
      assert.ok(Array.isArray(permissions.routes.patch))
      assert.ok(Array.isArray(permissions.routes.delete))
    })
  })
})
