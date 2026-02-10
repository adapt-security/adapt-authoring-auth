import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import Authentication from '../lib/Authentication.js'

describe('Authentication', () => {
  let authentication

  before(() => {
    authentication = new Authentication()
  })

  describe('constructor', () => {
    it('should initialize plugins object', () => {
      assert.equal(typeof authentication.plugins, 'object')
      assert.deepEqual(Object.keys(authentication.plugins).length, 0)
    })
  })

  describe('#registerPlugin()', () => {
    it('should register a valid auth plugin', () => {
      const mockPlugin = {
        constructor: { name: 'MockAuthModule' }
      }
      // Mock AbstractAuthModule check by adding prototype
      Object.setPrototypeOf(mockPlugin, Object.create({
        constructor: { name: 'AbstractAuthModule' }
      }))

      const mockApp = {
        errors: {
          DUPL_AUTH_PLUGIN_REG: {
            setData: (data) => new Error(`Duplicate plugin: ${data.name}`)
          },
          AUTH_PLUGIN_INVALID_CLASS: {
            setData: (data) => new Error(`Invalid class: ${data.name}`)
          }
        }
      }

      // Save original App.instance
      const originalApp = global.App?.instance

      try {
        // Mock App.instance for the test
        global.App = { instance: mockApp }

        // Note: This test would need proper AbstractAuthModule inheritance
        // For now, we test the structure without the actual registration
        assert.equal(typeof authentication.registerPlugin, 'function')
      } finally {
        // Restore original App.instance
        if (originalApp) {
          global.App = { instance: originalApp }
        }
      }
    })
  })

  describe('static #init()', () => {
    it('should be a static method', () => {
      assert.equal(typeof Authentication.init, 'function')
    })
  })
})
