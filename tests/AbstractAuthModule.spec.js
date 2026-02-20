import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { Hook } from 'adapt-authoring-core'
import AbstractAuthModule from '../lib/AbstractAuthModule.js'

function createMockApp () {
  const moduleLoadedHook = new Hook()
  return {
    logger: { log: () => {} },
    dependencyloader: { moduleLoadedHook },
    errors: {
      FUNC_NOT_OVERRIDDEN: {
        setData: (data) => new Error(`Function not overridden: ${data.name}`)
      },
      INVALID_LOGIN_DETAILS: Object.assign(new Error('Invalid login'), { code: 'INVALID_LOGIN_DETAILS' }),
      USER_REG_FAILED: {
        setData: (data) => Object.assign(new Error('Registration failed'), { code: 'USER_REG_FAILED', ...data })
      }
    },
    lang: { translate: (_, e) => e.message || String(e) }
  }
}

describe('AbstractAuthModule', () => {
  describe('constructor', () => {
    it('should be instantiable', () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      assert.ok(module instanceof AbstractAuthModule)
    })
  })

  describe('#setValues()', () => {
    it('should set default values', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      await module.setValues()
      assert.equal(module.type, undefined)
      assert.equal(module.routes, undefined)
      assert.equal(module.userSchema, 'user')
    })

    it('should be callable multiple times without error', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      await module.setValues()
      await module.setValues()
      assert.equal(module.userSchema, 'user')
    })

    it('should reset type to undefined', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      module.type = 'local'
      await module.setValues()
      assert.equal(module.type, undefined)
    })

    it('should reset routes to undefined', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      module.routes = [{ route: '/test' }]
      await module.setValues()
      assert.equal(module.routes, undefined)
    })

    it('should always set userSchema to user', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      module.userSchema = 'custom'
      await module.setValues()
      assert.equal(module.userSchema, 'user')
    })
  })

  describe('#authenticate()', () => {
    it('should throw FUNC_NOT_OVERRIDDEN error when not overridden', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })

      try {
        await module.authenticate({}, {}, {})
        assert.fail('Should have thrown error')
      } catch (e) {
        assert.ok(e.message.includes('authenticate'))
      }
    })

    it('should include the class name in the error', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })

      try {
        await module.authenticate({}, {}, {})
        assert.fail('Should have thrown error')
      } catch (e) {
        assert.ok(e.message.includes('AbstractAuthModule'))
      }
    })
  })

  describe('#secureRoute()', () => {
    it('should delegate to auth.secureRoute with prefixed path', () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const secured = []
      module.auth = {
        secureRoute: (route, method, scopes) => secured.push({ route, method, scopes })
      }
      module.router = { path: '/api/auth/local' }

      module.secureRoute('/register', 'post', ['register:users'])
      assert.equal(secured.length, 1)
      assert.equal(secured[0].route, '/api/auth/local/register')
      assert.equal(secured[0].method, 'post')
      assert.deepEqual(secured[0].scopes, ['register:users'])
    })

    it('should handle root route path', () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const secured = []
      module.auth = {
        secureRoute: (route, method, scopes) => secured.push({ route, method, scopes })
      }
      module.router = { path: '/api/auth/local' }

      module.secureRoute('/', 'get', ['read:auth'])
      assert.equal(secured[0].route, '/api/auth/local/')
    })

    it('should pass multiple scopes through', () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const secured = []
      module.auth = {
        secureRoute: (route, method, scopes) => secured.push({ route, method, scopes })
      }
      module.router = { path: '/api/auth/local' }

      module.secureRoute('/admin', 'post', ['write:users', 'admin:all'])
      assert.deepEqual(secured[0].scopes, ['write:users', 'admin:all'])
    })
  })

  describe('#unsecureRoute()', () => {
    it('should delegate to auth.unsecureRoute with prefixed path', () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const unsecured = []
      module.auth = {
        unsecureRoute: (route, method) => unsecured.push({ route, method })
      }
      module.router = { path: '/api/auth/local' }

      module.unsecureRoute('/', 'post')
      assert.equal(unsecured.length, 1)
      assert.equal(unsecured[0].route, '/api/auth/local/')
      assert.equal(unsecured[0].method, 'post')
    })

    it('should handle nested route path', () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const unsecured = []
      module.auth = {
        unsecureRoute: (route, method) => unsecured.push({ route, method })
      }
      module.router = { path: '/api/auth/local' }

      module.unsecureRoute('/callback', 'get')
      assert.equal(unsecured[0].route, '/api/auth/local/callback')
    })
  })

  describe('#register()', () => {
    it('should delegate to authentication.registerUser', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const expectedResult = { _id: '123', email: 'test@test.com' }
      module.type = 'local'
      module.auth = {
        authentication: {
          registerUser: (type, data) => {
            assert.equal(type, 'local')
            return expectedResult
          }
        }
      }

      const result = await module.register({ email: 'test@test.com' })
      assert.deepEqual(result, expectedResult)
    })

    it('should pass the module type to registerUser', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      let capturedType
      module.type = 'oauth'
      module.auth = {
        authentication: {
          registerUser: (type, data) => { capturedType = type; return {} }
        }
      }

      await module.register({ email: 'test@test.com' })
      assert.equal(capturedType, 'oauth')
    })
  })

  describe('#setUserEnabled()', () => {
    it('should call users.update with correct params', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      let updateArgs
      module.users = {
        update: (query, data) => { updateArgs = { query, data } }
      }

      await module.setUserEnabled({ _id: 'user123' }, true)
      assert.deepEqual(updateArgs.query, { _id: 'user123' })
      assert.deepEqual(updateArgs.data, { isEnabled: true })
    })

    it('should pass false to disable a user', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      let updateArgs
      module.users = {
        update: (query, data) => { updateArgs = { query, data } }
      }

      await module.setUserEnabled({ _id: 'user123' }, false)
      assert.deepEqual(updateArgs.data, { isEnabled: false })
    })

    it('should use user._id in the query', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      let capturedQuery
      module.users = {
        update: (query) => { capturedQuery = query }
      }

      await module.setUserEnabled({ _id: 'abc', name: 'test' }, true)
      assert.deepEqual(capturedQuery, { _id: 'abc' })
    })
  })

  describe('#disavowUser()', () => {
    it('should delegate to authentication.disavowUser', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const expectedResult = { ok: true }
      module.auth = {
        authentication: {
          disavowUser: (query) => {
            assert.deepEqual(query, { userId: '123' })
            return expectedResult
          }
        }
      }

      const result = await module.disavowUser({ userId: '123' })
      assert.deepEqual(result, expectedResult)
    })

    it('should pass query through unchanged', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      let capturedQuery
      module.auth = {
        authentication: {
          disavowUser: (query) => { capturedQuery = query; return {} }
        }
      }

      const query = { userId: 'u1', signature: 'sig' }
      await module.disavowUser(query)
      assert.deepEqual(capturedQuery, query)
    })
  })

  describe('#authenticateHandler()', () => {
    it('should send error if user is not found', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const sentError = {}
      module.users = { find: () => [] }
      const req = { body: { email: 'noone@test.com' } }
      const res = { sendError: (e) => { sentError.error = e } }

      await module.authenticateHandler(req, res, () => {})
      assert.equal(sentError.error, module.app.errors.INVALID_LOGIN_DETAILS)
    })

    it('should call authenticate and set session token on success', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const user = { _id: '123', email: 'test@test.com' }
      module.users = { find: () => [user] }
      module.authenticate = async () => {}
      module.log = () => {}

      let statusCode
      let jsonCalled = false
      const req = {
        body: { email: 'test@test.com', persistSession: false },
        session: { cookie: { maxAge: 3600 }, token: null }
      }
      const res = {
        status: (code) => { statusCode = code; return res },
        json: () => { jsonCalled = true }
      }

      const { default: AuthToken } = await import('../lib/AuthToken.js')
      const originalGenerate = AuthToken.generate
      AuthToken.generate = async () => 'mock-token'

      try {
        await module.authenticateHandler(req, res, () => {})
        assert.equal(statusCode, 204)
        assert.equal(jsonCalled, true)
        assert.equal(req.session.cookie.maxAge, null)
        assert.equal(req.session.token, 'mock-token')
      } finally {
        AuthToken.generate = originalGenerate
      }
    })

    it('should send error if authenticate throws', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const user = { _id: '123', email: 'test@test.com' }
      const authError = new Error('bad password')
      module.users = { find: () => [user] }
      module.authenticate = async () => { throw authError }
      module.log = () => {}

      let sentError
      const req = { body: { email: 'test@test.com' } }
      const res = { sendError: (e) => { sentError = e } }

      await module.authenticateHandler(req, res, () => {})
      assert.equal(sentError, authError)
    })

    it('should set maxAge to null when persistSession is not true', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const user = { _id: '1', email: 'test@test.com' }
      module.users = { find: () => [user] }
      module.authenticate = async () => {}
      module.log = () => {}

      const req = {
        body: { email: 'test@test.com', persistSession: false },
        session: { cookie: { maxAge: 9999 }, token: null }
      }
      const res = {
        status: () => res,
        json: () => {}
      }

      const { default: AuthToken } = await import('../lib/AuthToken.js')
      const originalGenerate = AuthToken.generate
      AuthToken.generate = async () => 'tok'
      try {
        await module.authenticateHandler(req, res, () => {})
        assert.equal(req.session.cookie.maxAge, null)
      } finally {
        AuthToken.generate = originalGenerate
      }
    })

    it('should handle missing session gracefully', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const user = { _id: '1', email: 'test@test.com' }
      module.users = { find: () => [user] }
      module.authenticate = async () => {}
      module.log = () => {}

      let statusCode
      const req = { body: { email: 'test@test.com' } }
      const res = {
        status: (code) => { statusCode = code; return res },
        json: () => {}
      }

      await module.authenticateHandler(req, res, () => {})
      assert.equal(statusCode, 204)
    })

    it('should log debug on failed login', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const user = { _id: { toString: () => 'u1' }, email: 'test@test.com' }
      module.users = { find: () => [user] }
      module.authenticate = async () => { throw new Error('fail') }
      let logCalled = false
      module.log = () => { logCalled = true }

      const req = { body: { email: 'test@test.com' } }
      const res = { sendError: () => {} }

      await module.authenticateHandler(req, res, () => {})
      assert.equal(logCalled, true)
    })
  })

  describe('#enableHandler()', () => {
    it('should enable a user when URL is /enable', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const user = { _id: 'u1' }
      let enabledValue
      module.users = { find: () => [user] }
      module.setUserEnabled = async (u, enabled) => { enabledValue = enabled }
      module.log = () => {}

      let statusCode
      const req = {
        body: { _id: 'u1' },
        url: '/enable',
        auth: { user: { _id: { toString: () => 'admin1' } } }
      }
      const res = {
        status: (code) => { statusCode = code; return res },
        json: () => {}
      }

      await module.enableHandler(req, res, () => {})
      assert.equal(enabledValue, true)
      assert.equal(statusCode, 204)
    })

    it('should disable a user when URL is not /enable', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const user = { _id: 'u1' }
      let enabledValue
      module.users = { find: () => [user] }
      module.setUserEnabled = async (u, enabled) => { enabledValue = enabled }
      module.log = () => {}

      const req = {
        body: { _id: 'u1' },
        url: '/disable',
        auth: { user: { _id: { toString: () => 'admin1' } } }
      }
      const res = {
        status: () => { return res },
        json: () => {}
      }

      await module.enableHandler(req, res, () => {})
      assert.equal(enabledValue, false)
    })

    it('should call next with error on failure', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const error = new Error('user not found')
      module.users = { find: () => { throw error } }

      let nextError
      const req = { body: { _id: 'u1' }, url: '/enable' }
      const res = {}

      await module.enableHandler(req, res, (e) => { nextError = e })
      assert.equal(nextError, error)
    })

    it('should pass the found user to setUserEnabled', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const user = { _id: 'u1', email: 'test@test.com' }
      let capturedUser
      module.users = { find: () => [user] }
      module.setUserEnabled = async (u) => { capturedUser = u }
      module.log = () => {}

      const req = {
        body: { _id: 'u1' },
        url: '/enable',
        auth: { user: { _id: { toString: () => 'admin' } } }
      }
      const res = { status: () => res, json: () => {} }

      await module.enableHandler(req, res, () => {})
      assert.equal(capturedUser, user)
    })
  })

  describe('#registerHandler()', () => {
    it('should register user and return result', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const newUser = { _id: '456', email: 'new@test.com' }
      module.registerHook = new Hook({ mutable: true })
      module.register = async () => newUser
      module.log = () => {}

      let jsonResult
      const req = {
        body: { email: 'new@test.com' },
        auth: { user: { _id: { toString: () => 'admin1' } } }
      }
      const res = { json: (data) => { jsonResult = data } }

      await module.registerHandler(req, res, () => {})
      assert.deepEqual(jsonResult, newUser)
    })

    it('should set apiData if not already set', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      module.registerHook = new Hook({ mutable: true })
      module.register = async () => ({ _id: '1' })
      module.log = () => {}

      const req = {
        body: { email: 'a@b.com' },
        auth: { user: { _id: { toString: () => 'admin' } } }
      }
      const res = { json: () => {} }

      await module.registerHandler(req, res, () => {})
      assert.deepEqual(req.apiData, { modifying: true, data: req.body })
    })

    it('should call next with USER_REG_FAILED on error', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const error = new Error('registration failed')
      module.registerHook = new Hook({ mutable: true })
      module.register = async () => { throw error }

      let nextArg
      const req = {
        body: { email: 'fail@test.com' },
        translate: (e) => e.message
      }
      const res = {}

      await module.registerHandler(req, res, (e) => { nextArg = e })
      assert.equal(nextArg.code, 'USER_REG_FAILED')
    })

    it('should preserve existing apiData', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      module.registerHook = new Hook({ mutable: true })
      module.register = async () => ({ _id: '1' })
      module.log = () => {}

      const existingApiData = { modifying: false, data: { custom: true } }
      const req = {
        body: { email: 'a@b.com' },
        apiData: existingApiData,
        auth: { user: { _id: { toString: () => 'admin' } } }
      }
      const res = { json: () => {} }

      await module.registerHandler(req, res, () => {})
      assert.equal(req.apiData, existingApiData)
    })

    it('should invoke registerHook before registering', async () => {
      const module = new AbstractAuthModule(createMockApp(), { name: 'test-auth' })
      const callOrder = []
      module.registerHook = new Hook({ mutable: true })
      module.registerHook.tap((req) => { callOrder.push('hook') })
      module.register = async () => { callOrder.push('register'); return { _id: '1' } }
      module.log = () => {}

      const req = {
        body: { email: 'a@b.com' },
        auth: { user: { _id: { toString: () => 'admin' } } }
      }
      const res = { json: () => {} }

      await module.registerHandler(req, res, () => {})
      assert.deepEqual(callOrder, ['hook', 'register'])
    })
  })
})
