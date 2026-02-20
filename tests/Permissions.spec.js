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
          { getConfig: () => false },
          { api: { flattenRouters: () => [] } }
        ]
      })
    })
    permissions = await Permissions.init()
  })

  after(() => {
    restoreAppInstance()
  })

  describe('static #init()', () => {
    it('should return a Permissions instance', async () => {
      mockAppInstance({
        onReady: () => Promise.resolve({
          waitForModule: async () => [
            { getConfig: () => false },
            { api: { flattenRouters: () => [] } }
          ]
        })
      })
      const instance = await Permissions.init()
      assert.ok(instance instanceof Permissions)
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

    it('should have five HTTP method keys', () => {
      assert.equal(Object.keys(permissions.routes).length, 5)
    })
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

    it('should handle routes with no path parameters', () => {
      permissions.secureRoute('/api/static/endpoint', 'get', ['read:static'])
      const scopes = permissions.getScopesForRoute('get', '/api/static/endpoint')
      assert.deepEqual(scopes, ['read:static'])
    })

    it('should allow securing same path for different methods', () => {
      permissions.secureRoute('/api/dual', 'get', ['read:dual'])
      permissions.secureRoute('/api/dual', 'post', ['write:dual'])
      assert.deepEqual(permissions.getScopesForRoute('get', '/api/dual'), ['read:dual'])
      assert.deepEqual(permissions.getScopesForRoute('post', '/api/dual'), ['write:dual'])
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

    it('should return undefined for completely unknown route', () => {
      const scopes = permissions.getScopesForRoute('get', '/totally/unknown/route')
      assert.equal(scopes, undefined)
    })

    it('should return first matching route scopes', () => {
      permissions.secureRoute('/api/first/:id', 'get', ['read:first'])
      const scopes = permissions.getScopesForRoute('get', '/api/first/test')
      assert.deepEqual(scopes, ['read:first'])
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

    it('should throw UNAUTHORISED when user lacks required scopes', async () => {
      mockAppInstance({
        onReady: () => Promise.resolve({
          waitForModule: async () => [
            { getConfig: () => false, log: () => {} },
            { api: { flattenRouters: () => [] } }
          ]
        }),
        waitForModule: async () => ({ log: () => {} }),
        errors: {
          UNAUTHORISED: Object.assign(
            new Error('Unauthorised'),
            { code: 'UNAUTHORISED', setData: function (d) { Object.assign(this, d); return this } }
          )
        }
      })

      const p = new Permissions()
      p.secureRoute('/api/secret', 'get', ['admin:secret'])

      const req = {
        baseUrl: '/api',
        path: '/secret',
        method: 'get',
        auth: { isSuper: false, scopes: ['read:public'] }
      }

      await assert.rejects(() => p.check(req))
    })

    it('should throw UNAUTHORISED when user has empty scopes', async () => {
      mockAppInstance({
        onReady: () => Promise.resolve({
          waitForModule: async () => [
            { getConfig: () => false, log: () => {} },
            { api: { flattenRouters: () => [] } }
          ]
        }),
        waitForModule: async () => ({ log: () => {} }),
        errors: {
          UNAUTHORISED: Object.assign(
            new Error('Unauthorised'),
            { code: 'UNAUTHORISED', setData: function (d) { Object.assign(this, d); return this } }
          )
        }
      })

      const p = new Permissions()
      p.secureRoute('/api/protected', 'get', ['read:protected'])

      const req = {
        baseUrl: '/api',
        path: '/protected',
        method: 'get',
        auth: { isSuper: false, scopes: [] }
      }

      await assert.rejects(() => p.check(req))
    })

    it('should use lowercase method for scope lookup', async () => {
      permissions.secureRoute('/api/methodtest', 'post', ['write:methodtest'])

      const req = {
        baseUrl: '/api',
        path: '/methodtest',
        method: 'POST',
        auth: { isSuper: false, scopes: ['write:methodtest'] }
      }

      await assert.doesNotReject(() => permissions.check(req))
    })

    it('should handle path without trailing slash', async () => {
      permissions.secureRoute('/api/noslash', 'get', ['read:noslash'])

      const req = {
        baseUrl: '/api',
        path: '/noslash',
        method: 'get',
        auth: { isSuper: false, scopes: ['read:noslash'] }
      }

      await assert.doesNotReject(() => permissions.check(req))
    })

    it('should default to empty scopes array when req.auth.scopes is undefined', async () => {
      mockAppInstance({
        onReady: () => Promise.resolve({
          waitForModule: async () => [
            { getConfig: () => false, log: () => {} },
            { api: { flattenRouters: () => [] } }
          ]
        }),
        waitForModule: async () => ({ log: () => {} }),
        errors: {
          UNAUTHORISED: Object.assign(
            new Error('Unauthorised'),
            { code: 'UNAUTHORISED', setData: function (d) { Object.assign(this, d); return this } }
          )
        }
      })

      const p = new Permissions()
      p.secureRoute('/api/noscopes', 'get', ['read:noscopes'])

      const req = {
        baseUrl: '/api',
        path: '/noscopes',
        method: 'get',
        auth: { isSuper: false }
      }

      await assert.rejects(() => p.check(req))
    })
  })
})
