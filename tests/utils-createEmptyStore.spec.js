import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createEmptyStore } from '../lib/utils/createEmptyStore.js'

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

  it('should contain the correct HTTP method keys', () => {
    const store = createEmptyStore()
    const keys = Object.keys(store).sort()
    assert.deepEqual(keys, ['delete', 'get', 'patch', 'post', 'put'])
  })

  it('should allow mutation of returned arrays', () => {
    const store = createEmptyStore()
    store.get.push('/api/test')
    assert.equal(store.get.length, 1)
    assert.equal(store.get[0], '/api/test')
  })

  it('should not share arrays between stores', () => {
    const store1 = createEmptyStore()
    const store2 = createEmptyStore()
    store1.post.push('/api/one')
    assert.equal(store1.post.length, 1)
    assert.equal(store2.post.length, 0)
  })
})
