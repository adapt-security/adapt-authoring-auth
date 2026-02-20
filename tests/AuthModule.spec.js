import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { Hook } from 'adapt-authoring-core'
import AuthModule from '../lib/AuthModule.js'

function createMockApp () {
  const moduleLoadedHook = new Hook()
  return {
    logger: { log: () => {} },
    dependencyloader: { moduleLoadedHook },
    config: { get: () => undefined }
  }
}

describe('AuthModule', () => {
  describe('constructor', () => {
    it('should be instantiable', () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      assert.ok(authModule instanceof AuthModule)
    })
  })

  describe('#unsecureRoute()', () => {
    it('should mark route as unsecured', () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      authModule.unsecuredRoutes = { post: {}, get: {}, put: {}, patch: {}, delete: {} }
      authModule.log = () => {}

      authModule.unsecureRoute('/api/test', 'post')
      assert.equal(authModule.unsecuredRoutes.post['/api/test'], true)
    })

    it('should handle different HTTP methods', () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      authModule.unsecuredRoutes = { post: {}, get: {}, put: {}, patch: {}, delete: {} }
      authModule.log = () => {}

      authModule.unsecureRoute('/api/another', 'get')
      assert.equal(authModule.unsecuredRoutes.get['/api/another'], true)
      assert.equal(authModule.unsecuredRoutes.post['/api/another'], undefined)
    })

    it('should handle case-insensitive HTTP methods', () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      authModule.unsecuredRoutes = { post: {}, get: {}, put: {}, patch: {}, delete: {} }
      authModule.log = () => {}

      authModule.unsecureRoute('/api/case', 'POST')
      assert.equal(authModule.unsecuredRoutes.post['/api/case'], true)
    })

    it('should allow multiple routes for same method', () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      authModule.unsecuredRoutes = { post: {}, get: {}, put: {}, patch: {}, delete: {} }
      authModule.log = () => {}

      authModule.unsecureRoute('/api/a', 'get')
      authModule.unsecureRoute('/api/b', 'get')
      assert.equal(authModule.unsecuredRoutes.get['/api/a'], true)
      assert.equal(authModule.unsecuredRoutes.get['/api/b'], true)
    })

    it('should log a warning when unsecuring a route', () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      authModule.unsecuredRoutes = { post: {}, get: {}, put: {}, patch: {}, delete: {} }
      let logLevel
      authModule.log = (level) => { logLevel = level }

      authModule.unsecureRoute('/api/test', 'get')
      assert.equal(logLevel, 'warn')
    })

    it('should handle all five HTTP methods', () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      authModule.unsecuredRoutes = { post: {}, get: {}, put: {}, patch: {}, delete: {} }
      authModule.log = () => {}

      authModule.unsecureRoute('/r1', 'get')
      authModule.unsecureRoute('/r2', 'post')
      authModule.unsecureRoute('/r3', 'put')
      authModule.unsecureRoute('/r4', 'patch')
      authModule.unsecureRoute('/r5', 'delete')
      assert.equal(authModule.unsecuredRoutes.get['/r1'], true)
      assert.equal(authModule.unsecuredRoutes.post['/r2'], true)
      assert.equal(authModule.unsecuredRoutes.put['/r3'], true)
      assert.equal(authModule.unsecuredRoutes.patch['/r4'], true)
      assert.equal(authModule.unsecuredRoutes.delete['/r5'], true)
    })
  })

  describe('#secureRoute()', () => {
    it('should delegate to permissions.secureRoute', () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      const secured = []
      authModule.permissions = {
        secureRoute: (route, method, scopes) => secured.push({ route, method, scopes })
      }

      authModule.secureRoute('/api/users', 'get', ['read:users'])
      assert.equal(secured.length, 1)
      assert.equal(secured[0].route, '/api/users')
      assert.equal(secured[0].method, 'get')
      assert.deepEqual(secured[0].scopes, ['read:users'])
    })

    it('should pass all arguments through', () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      let capturedArgs
      authModule.permissions = {
        secureRoute: (...args) => { capturedArgs = args }
      }

      authModule.secureRoute('/api/test', 'post', ['a:b', 'c:d'])
      assert.equal(capturedArgs[0], '/api/test')
      assert.equal(capturedArgs[1], 'post')
      assert.deepEqual(capturedArgs[2], ['a:b', 'c:d'])
    })
  })

  describe('#initAuthData()', () => {
    it('should call AuthUtils.initAuthData', async () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      authModule.isEnabled = false

      const req = { get: () => undefined, headers: {} }
      await authModule.initAuthData(req)
      assert.deepEqual(req.auth, {})
    })

    it('should set req.auth when no Authorization header exists', async () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      authModule.isEnabled = false

      const req = { get: () => null, headers: {} }
      await authModule.initAuthData(req)
      assert.deepEqual(req.auth, {})
    })

    it('should parse auth header when present', async () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      authModule.isEnabled = false

      const req = {
        get: (h) => h === 'Authorization' ? 'Bearer tok123' : undefined,
        headers: {}
      }
      await authModule.initAuthData(req)
      assert.equal(req.auth.header.type, 'Bearer')
      assert.equal(req.auth.header.value, 'tok123')
    })
  })

  describe('#rootMiddleware()', () => {
    it('should call next after initAuthData resolves', async () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      authModule.isEnabled = false

      let nextCalled = false
      const req = { get: () => undefined, headers: {} }
      const res = {}

      await new Promise((resolve) => {
        authModule.rootMiddleware(req, res, () => {
          nextCalled = true
          resolve()
        })
      })
      assert.equal(nextCalled, true)
    })

    it('should call next even if initAuthData fails', async () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      authModule.isEnabled = true
      authModule.initAuthData = async () => { throw new Error('fail') }

      let nextCalled = false
      const req = {}
      const res = {}

      await new Promise((resolve) => {
        authModule.rootMiddleware(req, res, () => {
          nextCalled = true
          resolve()
        })
      })
      assert.equal(nextCalled, true)
    })
  })

  describe('#apiMiddleware()', () => {
    it('should call next for unsecured routes without auth', async () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      authModule.unsecuredRoutes = { get: { '/api/auth/check': true }, post: {}, put: {}, patch: {}, delete: {} }
      authModule.isEnabled = false

      let nextCalled = false
      const req = {
        get: () => undefined,
        headers: {},
        method: 'GET',
        baseUrl: '/api/auth',
        route: { path: '/check/' },
        originalUrl: '/api/auth/check'
      }
      const res = { sendError: () => {} }

      await authModule.apiMiddleware(req, res, () => { nextCalled = true })
      assert.equal(nextCalled, true)
    })

    it('should send error for secured routes when initAuthData fails', async () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      authModule.unsecuredRoutes = { get: {}, post: {}, put: {}, patch: {}, delete: {} }
      authModule.log = () => {}
      const initError = { statusCode: 401, message: 'Unauthenticated' }
      authModule.initAuthData = async () => { throw initError }

      let sentError
      const req = {
        method: 'GET',
        baseUrl: '/api',
        route: { path: '/users/' },
        originalUrl: '/api/users'
      }
      const res = { sendError: (e) => { sentError = e } }

      await authModule.apiMiddleware(req, res, () => {})
      assert.equal(sentError, initError)
    })

    it('should check permissions for secured routes', async () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      authModule.unsecuredRoutes = { get: {}, post: {}, put: {}, patch: {}, delete: {} }
      authModule.isEnabled = false
      let permissionsChecked = false
      authModule.permissions = {
        check: async () => { permissionsChecked = true }
      }

      const req = {
        get: () => undefined,
        headers: {},
        method: 'GET',
        baseUrl: '/api',
        route: { path: '/secure/' },
        originalUrl: '/api/secure'
      }
      const res = {}

      await authModule.apiMiddleware(req, res, () => {})
      assert.equal(permissionsChecked, true)
    })

    it('should match unsecured short route (without trailing segment)', async () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      authModule.unsecuredRoutes = { get: { '/api/public': true }, post: {}, put: {}, patch: {}, delete: {} }
      authModule.isEnabled = false

      let nextCalled = false
      const req = {
        get: () => undefined,
        headers: {},
        method: 'GET',
        baseUrl: '/api',
        route: { path: '/public/:id' },
        originalUrl: '/api/public/123'
      }
      const res = {}

      await authModule.apiMiddleware(req, res, () => { nextCalled = true })
      assert.equal(nextCalled, true)
    })

    it('should skip permissions check for unsecured route when initAuthData fails', async () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      authModule.unsecuredRoutes = { get: { '/api/open': true }, post: {}, put: {}, patch: {}, delete: {} }
      authModule.log = () => {}
      authModule.initAuthData = async () => { throw new Error('no auth') }
      let permissionsChecked = false
      authModule.permissions = {
        check: async () => { permissionsChecked = true }
      }

      let nextCalled = false
      const req = {
        method: 'GET',
        baseUrl: '/api',
        route: { path: '/open/' },
        originalUrl: '/api/open'
      }
      const res = { sendError: () => {} }

      await authModule.apiMiddleware(req, res, () => { nextCalled = true })
      assert.equal(nextCalled, true)
      assert.equal(permissionsChecked, false)
    })

    it('should lowercase the request method for route lookup', async () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      authModule.unsecuredRoutes = { get: {}, post: { '/api/test': true }, put: {}, patch: {}, delete: {} }
      authModule.isEnabled = false

      let nextCalled = false
      const req = {
        get: () => undefined,
        headers: {},
        method: 'POST',
        baseUrl: '/api',
        route: { path: '/test/' },
        originalUrl: '/api/test'
      }
      const res = {}

      await authModule.apiMiddleware(req, res, () => { nextCalled = true })
      assert.equal(nextCalled, true)
    })
  })
})
