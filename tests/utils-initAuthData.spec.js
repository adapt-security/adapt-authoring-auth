import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { initAuthData } from '../lib/utils/initAuthData.js'

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

  it('should handle empty Authorization header', async () => {
    const req = {
      get: (header) => header === 'Authorization' ? '' : undefined,
      headers: {}
    }
    await initAuthData(req)
    assert.deepEqual(req.auth, {})
  })

  it('should handle Authorization header with multiple spaces', async () => {
    const req = {
      get: (header) => header === 'Authorization' ? 'Bearer token with spaces' : undefined,
      headers: {}
    }
    await initAuthData(req)
    assert.equal(req.auth.header.type, 'Bearer')
    assert.equal(req.auth.header.value, 'token')
  })
})
