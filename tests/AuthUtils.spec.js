import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import AuthUtils from '../lib/AuthUtils.js'

describe('AuthUtils', () => {
  describe('#createEmptyStore()', () => {
    it('should return an object with empty arrays for HTTP methods', () => {
      const store = AuthUtils.createEmptyStore()
      assert.equal(typeof store, 'object')
      assert.ok(Array.isArray(store.post))
      assert.ok(Array.isArray(store.get))
      assert.ok(Array.isArray(store.put))
      assert.ok(Array.isArray(store.patch))
      assert.ok(Array.isArray(store.delete))
      assert.equal(store.post.length, 0)
      assert.equal(store.get.length, 0)
      assert.equal(store.put.length, 0)
      assert.equal(store.patch.length, 0)
      assert.equal(store.delete.length, 0)
    })

    it('should return exactly five HTTP method keys', () => {
      const store = AuthUtils.createEmptyStore()
      assert.equal(Object.keys(store).length, 5)
    })

    it('should return a new object each time', () => {
      const store1 = AuthUtils.createEmptyStore()
      const store2 = AuthUtils.createEmptyStore()
      assert.notEqual(store1, store2)
      assert.notEqual(store1.post, store2.post)
    })

    it('should include all five standard HTTP methods', () => {
      const store = AuthUtils.createEmptyStore()
      const keys = Object.keys(store)
      assert.ok(keys.includes('post'))
      assert.ok(keys.includes('get'))
      assert.ok(keys.includes('put'))
      assert.ok(keys.includes('patch'))
      assert.ok(keys.includes('delete'))
    })

    it('should have independent arrays that do not share references', () => {
      const store = AuthUtils.createEmptyStore()
      store.get.push('test')
      assert.equal(store.get.length, 1)
      assert.equal(store.post.length, 0)
    })

    it('should not affect other stores when modified', () => {
      const store1 = AuthUtils.createEmptyStore()
      const store2 = AuthUtils.createEmptyStore()
      store1.get.push('route1')
      assert.equal(store1.get.length, 1)
      assert.equal(store2.get.length, 0)
    })
  })

  describe('#initAuthData()', () => {
    it('should initialize req.auth as empty object when no auth header', async () => {
      const req = {
        get: () => undefined,
        headers: {}
      }
      await AuthUtils.initAuthData(req)
      assert.deepEqual(req.auth, {})
    })

    it('should parse Authorization header with Bearer token', async () => {
      const req = {
        get: (header) => header === 'Authorization' ? 'Bearer abc123' : undefined,
        headers: {}
      }
      await AuthUtils.initAuthData(req)
      assert.equal(typeof req.auth, 'object')
      assert.equal(typeof req.auth.header, 'object')
      assert.equal(req.auth.header.type, 'Bearer')
      assert.equal(req.auth.header.value, 'abc123')
    })

    it('should parse Authorization header from headers object', async () => {
      const req = {
        get: () => undefined,
        headers: { Authorization: 'Basic xyz789' }
      }
      await AuthUtils.initAuthData(req)
      assert.equal(typeof req.auth, 'object')
      assert.equal(typeof req.auth.header, 'object')
      assert.equal(req.auth.header.type, 'Basic')
      assert.equal(req.auth.header.value, 'xyz789')
    })

    it('should handle auth headers with only type', async () => {
      const req = {
        get: (header) => header === 'Authorization' ? 'Bearer' : undefined,
        headers: {}
      }
      await AuthUtils.initAuthData(req)
      assert.equal(typeof req.auth, 'object')
      assert.equal(typeof req.auth.header, 'object')
      assert.equal(req.auth.header.type, 'Bearer')
      assert.equal(req.auth.header.value, undefined)
    })

    it('should prefer req.get() over req.headers', async () => {
      const req = {
        get: (header) => header === 'Authorization' ? 'Bearer fromGet' : undefined,
        headers: { Authorization: 'Basic fromHeaders' }
      }
      await AuthUtils.initAuthData(req)
      assert.equal(req.auth.header.type, 'Bearer')
      assert.equal(req.auth.header.value, 'fromGet')
    })

    it('should overwrite any existing req.auth', async () => {
      const req = {
        get: () => undefined,
        headers: {},
        auth: { stale: true }
      }
      await AuthUtils.initAuthData(req)
      assert.deepEqual(req.auth, {})
      assert.equal(req.auth.stale, undefined)
    })

    it('should not set header property when no Authorization header', async () => {
      const req = {
        get: () => undefined,
        headers: {}
      }
      await AuthUtils.initAuthData(req)
      assert.equal(req.auth.header, undefined)
    })

    it('should handle token values containing spaces', async () => {
      const req = {
        get: () => 'Bearer token with spaces',
        headers: {}
      }
      await AuthUtils.initAuthData(req)
      assert.equal(req.auth.header.type, 'Bearer')
      assert.equal(req.auth.header.value, 'token')
    })

    it('should return undefined and still set auth when header is missing', async () => {
      const req = {
        get: () => null,
        headers: {}
      }
      const result = await AuthUtils.initAuthData(req)
      assert.equal(result, undefined)
      assert.deepEqual(req.auth, {})
    })

    it('should handle empty string Authorization header', async () => {
      const req = {
        get: () => '',
        headers: {}
      }
      await AuthUtils.initAuthData(req)
      assert.deepEqual(req.auth, {})
    })
  })

  describe('#getConfig()', () => {
    it('should be a static method', () => {
      assert.equal(typeof AuthUtils.getConfig, 'function')
    })
  })

  describe('#log()', () => {
    it('should be a static method', () => {
      assert.equal(typeof AuthUtils.log, 'function')
    })
  })
})
