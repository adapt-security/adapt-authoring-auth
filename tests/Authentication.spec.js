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
      }
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
  // Delete the overridden property to restore the original getter from the prototype
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
  })

  describe('static #init()', () => {
    it('should be a static method', () => {
      assert.equal(typeof Authentication.init, 'function')
    })
  })
})
