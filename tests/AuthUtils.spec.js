import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createEmptyStore } from '../lib/utils/createEmptyStore.js'
import { initAuthData } from '../lib/utils/initAuthData.js'

describe('AuthUtils', () => {
  describe('createEmptyStore()', () => {
    it('should return an object with empty arrays for HTTP methods', () => {
      const store = createEmptyStore()
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
      const store = createEmptyStore()
      assert.equal(Object.keys(store).length, 5)
    })

    it('should return a new object each time', () => {
      const store1 = createEmptyStore()
      const store2 = createEmptyStore()
      assert.notEqual(store1, store2)
      assert.notEqual(store1.post, store2.post)
    })
  })

  describe('initAuthData()', () => {
    it('should initialize req.auth as empty object when no auth header', async () => {
      const req = {
        get: () => undefined,
        headers: {}
      }
      await initAuthData(req)
      assert.deepEqual(req.auth, {})
    })

    it('should parse Authorization header with Bearer token', async () => {
      const req = {
        get: (header) => header === 'Authorization' ? 'Bearer abc123' : undefined,
        headers: {}
      }
      await initAuthData(req)
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
      await initAuthData(req)
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
      await initAuthData(req)
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
      await initAuthData(req)
      assert.equal(req.auth.header.type, 'Bearer')
      assert.equal(req.auth.header.value, 'fromGet')
    })

    it('should overwrite any existing req.auth', async () => {
      const req = {
        get: () => undefined,
        headers: {},
        auth: { stale: true }
      }
      await initAuthData(req)
      assert.deepEqual(req.auth, {})
      assert.equal(req.auth.stale, undefined)
    })
  })
})
