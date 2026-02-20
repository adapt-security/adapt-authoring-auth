import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { App, Hook } from 'adapt-authoring-core'
import Authentication from '../lib/Authentication.js'
import AbstractAuthModule from '../lib/AbstractAuthModule.js'

function createMockApp () {
  const moduleLoadedHook = new Hook()
  return {
    logger: { log: () => {} },
    dependencyloader: { moduleLoadedHook },
    errors: {
      DUPL_AUTH_PLUGIN_REG: {
        setData: (data) => Object.assign(new Error(`Duplicate plugin: ${data.name}`), { code: 'DUPL_AUTH_PLUGIN_REG' })
      },
      AUTH_PLUGIN_INVALID_CLASS: {
        setData: (data) => Object.assign(new Error(`Invalid class: ${data.name}`), { code: 'AUTH_PLUGIN_INVALID_CLASS' })
      },
      NOT_FOUND: {
        setData: (data) => Object.assign(new Error(`Not found: ${data.id}`), { code: 'NOT_FOUND' })
      },
      INVALID_PARAMS: {
        setData: (data) => Object.assign(new Error(`Invalid params: ${data.params}`), { code: 'INVALID_PARAMS' })
      },
      UNAUTHENTICATED: Object.assign(new Error('Unauthenticated'), { code: 'UNAUTHENTICATED' })
    }
  }
}

function mockAppInstance (mockApp) {
  Object.defineProperty(App, 'instance', {
    get: () => mockApp,
    configurable: true
  })
}

function restoreAppInstance () {
  delete App.instance
}

describe('Authentication', () => {
  let mockApp

  before(() => {
    mockApp = createMockApp()
    mockAppInstance(mockApp)
  })

  after(() => {
    restoreAppInstance()
  })

  describe('constructor', () => {
    it('should initialize plugins object', () => {
      const authentication = new Authentication()
      assert.equal(typeof authentication.plugins, 'object')
      assert.equal(Object.keys(authentication.plugins).length, 0)
    })

    it('should create an empty plugins object', () => {
      const authentication = new Authentication()
      assert.deepEqual(authentication.plugins, {})
    })
  })

  describe('#registerPlugin()', () => {
    it('should register a valid auth plugin', () => {
      const authentication = new Authentication()
      const plugin = new AbstractAuthModule(mockApp, { name: 'test-plugin' })
      authentication.registerPlugin('local', plugin)
      assert.equal(authentication.plugins.local, plugin)
    })

    it('should throw DUPL_AUTH_PLUGIN_REG for duplicate type', () => {
      const authentication = new Authentication()
      const plugin = new AbstractAuthModule(mockApp, { name: 'test-plugin' })
      authentication.registerPlugin('local', plugin)

      assert.throws(() => {
        authentication.registerPlugin('local', plugin)
      }, (err) => {
        assert.equal(err.code, 'DUPL_AUTH_PLUGIN_REG')
        return true
      })
    })

    it('should throw AUTH_PLUGIN_INVALID_CLASS for non-AbstractAuthModule instance', () => {
      const authentication = new Authentication()

      assert.throws(() => {
        authentication.registerPlugin('invalid', { type: 'invalid' })
      }, (err) => {
        assert.equal(err.code, 'AUTH_PLUGIN_INVALID_CLASS')
        return true
      })
    })

    it('should allow registering multiple different types', () => {
      const authentication = new Authentication()
      const plugin1 = new AbstractAuthModule(mockApp, { name: 'plugin1' })
      const plugin2 = new AbstractAuthModule(mockApp, { name: 'plugin2' })
      authentication.registerPlugin('local', plugin1)
      authentication.registerPlugin('oauth', plugin2)
      assert.equal(authentication.plugins.local, plugin1)
      assert.equal(authentication.plugins.oauth, plugin2)
      assert.equal(Object.keys(authentication.plugins).length, 2)
    })

    it('should throw for null instance', () => {
      const authentication = new Authentication()
      assert.throws(() => {
        authentication.registerPlugin('test', null)
      })
    })

    it('should throw for plain object instance', () => {
      const authentication = new Authentication()
      assert.throws(() => {
        authentication.registerPlugin('test', {})
      }, (err) => {
        assert.equal(err.code, 'AUTH_PLUGIN_INVALID_CLASS')
        return true
      })
    })

    it('should include type name in error data for duplicates', () => {
      const authentication = new Authentication()
      const plugin = new AbstractAuthModule(mockApp, { name: 'test-plugin' })
      authentication.registerPlugin('mytype', plugin)

      assert.throws(() => {
        authentication.registerPlugin('mytype', plugin)
      }, (err) => {
        assert.ok(err.message.includes('mytype'))
        return true
      })
    })

    it('should include type name in error data for invalid class', () => {
      const authentication = new Authentication()

      assert.throws(() => {
        authentication.registerPlugin('badplugin', {})
      }, (err) => {
        assert.ok(err.message.includes('badplugin'))
        return true
      })
    })
  })

  describe('#registerUser()', () => {
    it('should throw NOT_FOUND if auth plugin is not registered', async () => {
      const authentication = new Authentication()

      await assert.rejects(
        () => authentication.registerUser('nonexistent', { email: 'test@test.com' }),
        (err) => {
          assert.equal(err.code, 'NOT_FOUND')
          return true
        }
      )
    })

    it('should call users.insert with correct data when plugin exists', async () => {
      const authentication = new Authentication()
      const insertedData = {}
      mockApp.waitForModule = async () => ({
        insert: (data, opts) => {
          insertedData.data = data
          insertedData.opts = opts
          return data
        }
      })

      const plugin = new AbstractAuthModule(mockApp, { name: 'test-plugin' })
      plugin.userSchema = 'localuser'
      authentication.plugins.local = plugin

      await authentication.registerUser('local', { email: 'user@test.com' })
      assert.equal(insertedData.data.email, 'user@test.com')
      assert.equal(insertedData.data.authType, 'local')
      assert.equal(insertedData.opts.schemaName, 'localuser')
    })

    it('should include authType in inserted data', async () => {
      const authentication = new Authentication()
      let capturedData
      mockApp.waitForModule = async () => ({
        insert: (data, opts) => { capturedData = data; return data }
      })

      const plugin = new AbstractAuthModule(mockApp, { name: 'test-plugin' })
      plugin.userSchema = 'user'
      authentication.plugins.oauth = plugin

      await authentication.registerUser('oauth', { email: 'oauth@test.com', name: 'Test' })
      assert.equal(capturedData.authType, 'oauth')
      assert.equal(capturedData.email, 'oauth@test.com')
      assert.equal(capturedData.name, 'Test')
    })

    it('should use the plugin userSchema for insert options', async () => {
      const authentication = new Authentication()
      let capturedOpts
      mockApp.waitForModule = async () => ({
        insert: (data, opts) => { capturedOpts = opts; return data }
      })

      const plugin = new AbstractAuthModule(mockApp, { name: 'test-plugin' })
      plugin.userSchema = 'customschema'
      authentication.plugins.custom = plugin

      await authentication.registerUser('custom', { email: 'x@y.com' })
      assert.equal(capturedOpts.schemaName, 'customschema')
    })
  })

  describe('#disavowUser()', () => {
    it('should throw INVALID_PARAMS if userId is missing', async () => {
      const authentication = new Authentication()

      await assert.rejects(
        () => authentication.disavowUser({}),
        (err) => {
          assert.equal(err.code, 'INVALID_PARAMS')
          return true
        }
      )
    })

    it('should throw INVALID_PARAMS when query has no userId', async () => {
      const authentication = new Authentication()

      await assert.rejects(
        () => authentication.disavowUser({ signature: 'abc' }),
        (err) => {
          assert.equal(err.code, 'INVALID_PARAMS')
          return true
        }
      )
    })

    it('should throw INVALID_PARAMS for empty query', async () => {
      const authentication = new Authentication()

      await assert.rejects(
        () => authentication.disavowUser({}),
        (err) => {
          assert.ok(err.message.includes('userId'))
          return true
        }
      )
    })
  })

  describe('#checkHandler()', () => {
    it('should send UNAUTHENTICATED error when no auth header', async () => {
      const authentication = new Authentication()
      let sentError
      const req = { auth: {} }
      const res = {
        sendError: (e) => { sentError = e }
      }

      await authentication.checkHandler(req, res, () => {})
      assert.equal(sentError.code, 'UNAUTHENTICATED')
    })

    it('should call sendError for caught errors', async () => {
      const authentication = new Authentication()
      let sendErrorCalled = false
      const req = { auth: {} }
      const res = {
        sendError: () => { sendErrorCalled = true }
      }

      await authentication.checkHandler(req, res, () => {})
      assert.equal(sendErrorCalled, true)
    })
  })

  describe('#disavowHandler()', () => {
    it('should call next with error on failure', async () => {
      const authentication = new Authentication()
      const error = new Error('disavow failed')
      authentication.disavowUser = async () => { throw error }

      let nextArg
      const req = {
        auth: {
          user: { _id: 'u1' },
          token: { signature: 'sig123' }
        }
      }
      const res = {}

      await authentication.disavowHandler(req, res, (e) => { nextArg = e })
      assert.equal(nextArg, error)
    })
  })

  describe('#generateTokenHandler()', () => {
    it('should call next with error on failure', async () => {
      const authentication = new Authentication()
      let nextArg
      const req = {
        auth: { user: { _id: 'u1', email: 'test@test.com' } },
        body: { lifespan: '1h' }
      }
      const res = {}

      // AuthToken.generate will fail without proper App.instance setup
      await authentication.generateTokenHandler(req, res, (e) => { nextArg = e })
      assert.ok(nextArg instanceof Error || typeof nextArg === 'object')
    })
  })

  describe('#retrieveTokensHandler()', () => {
    it('should call next with error on failure', async () => {
      const authentication = new Authentication()
      let nextArg
      const req = {
        auth: { user: { _id: 'u1' } }
      }
      const res = {}

      // AuthToken.find will fail without proper App.instance setup
      await authentication.retrieveTokensHandler(req, res, (e) => { nextArg = e })
      assert.ok(nextArg instanceof Error || typeof nextArg === 'object')
    })
  })

  describe('static #init()', () => {
    it('should be a static method', () => {
      assert.equal(typeof Authentication.init, 'function')
    })
  })
})
