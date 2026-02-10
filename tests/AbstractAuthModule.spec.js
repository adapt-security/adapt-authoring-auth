import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import AbstractAuthModule from '../lib/AbstractAuthModule.js'

describe('AbstractAuthModule', () => {
  describe('constructor', () => {
    it('should be instantiable', () => {
      const module = new AbstractAuthModule()
      assert.ok(module instanceof AbstractAuthModule)
    })
  })

  describe('#setValues()', () => {
    it('should set default values', async () => {
      const module = new AbstractAuthModule()
      await module.setValues()
      assert.equal(module.type, undefined)
      assert.equal(module.routes, undefined)
      assert.equal(module.userSchema, 'user')
    })
  })

  describe('#authenticate()', () => {
    it('should throw FUNC_NOT_OVERRIDDEN error when not overridden', async () => {
      const module = new AbstractAuthModule()
      module.app = {
        errors: {
          FUNC_NOT_OVERRIDDEN: {
            setData: (data) => new Error(`Function not overridden: ${data.name}`)
          }
        }
      }

      try {
        await module.authenticate({}, {}, {})
        assert.fail('Should have thrown error')
      } catch (e) {
        assert.ok(e.message.includes('authenticate'))
      }
    })
  })
})
