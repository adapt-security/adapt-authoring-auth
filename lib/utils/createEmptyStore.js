/**
 * Returns a generic empty object for mapping values to HTTP methods
 * @return {RouteStore}
 * @memberof auth
 */
export function createEmptyStore () {
  /**
   * A key/value store linking API route/HTTP methods to values
   * @memberof auth
   * @typedef {Object} RouteStore
   * @property {Array} post Data relating to the post HTTP method
   * @property {Array} get Data relating to the get HTTP method
   * @property {Array} put Data relating to the put HTTP method
   * @property {Array} patch Data relating to the patch HTTP method
   * @property {Array} delete Data relating to the delete HTTP method
   */
  return {
    post: [],
    get: [],
    put: [],
    patch: [],
    delete: []
  }
}
