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
  })

  describe('#initAuthData()', () => {
    it('should call AuthUtils.initAuthData', async () => {
      const authModule = new AuthModule(createMockApp(), { name: 'test-auth' })
      authModule.isEnabled = false

      const req = { get: () => undefined, headers: {} }
      await authModule.initAuthData(req)
      assert.deepEqual(req.auth, {})
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
      // Force initAuthData to throw by making initAuthData fail
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
  })
})
