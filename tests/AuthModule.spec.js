import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import AuthModule from '../lib/AuthModule.js'

describe('AuthModule', () => {
  let authModule

  before(() => {
    authModule = new AuthModule()
  })

  describe('constructor', () => {
    it('should be instantiable', () => {
      assert.ok(authModule instanceof AuthModule)
    })
  })

  describe('#unsecureRoute()', () => {
    it('should mark route as unsecured', () => {
      authModule.unsecuredRoutes = {
        post: {},
        get: {},
        put: {},
        patch: {},
        delete: {}
      }
      authModule.log = () => {} // Mock log function

      authModule.unsecureRoute('/api/test', 'post')
      assert.equal(authModule.unsecuredRoutes.post['/api/test'], true)
    })

    it('should handle different HTTP methods', () => {
      authModule.unsecuredRoutes = {
        post: {},
        get: {},
        put: {},
        patch: {},
        delete: {}
      }
      authModule.log = () => {} // Mock log function

      authModule.unsecureRoute('/api/another', 'get')
      assert.equal(authModule.unsecuredRoutes.get['/api/another'], true)
      assert.equal(authModule.unsecuredRoutes.post['/api/another'], undefined)
    })

    it('should handle case-insensitive HTTP methods', () => {
      authModule.unsecuredRoutes = {
        post: {},
        get: {},
        put: {},
        patch: {},
        delete: {}
      }
      authModule.log = () => {} // Mock log function

      authModule.unsecureRoute('/api/case', 'POST')
      assert.equal(authModule.unsecuredRoutes.post['/api/case'], true)
    })
  })

  describe('#secureRoute()', () => {
    it('should be a method', () => {
      assert.equal(typeof authModule.secureRoute, 'function')
    })
  })
})
