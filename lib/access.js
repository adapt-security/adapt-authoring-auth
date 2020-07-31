const AuthError = require('./authError');
const AuthUtils = require('./authUtils');
/**
* Handles checking users access to server resources
*/
class Access {
  /**
  * Creates and instanciates the class
  * @return {Promise} Resolves with the instance
  */
  static async init() {
    return new Access();
  }
  /** @constructor */
  constructor() {
    /**
    * The registered access checking functions, grouped by HTTP method & route
    * @type {RouteStore}
    * @example
    * {
    *   post: { "/api/test": () => true }
    * }
    * // i.e.
    * this.plugins.post["/api/test"]; // () => true;
    */
    this.plugins = AuthUtils.createEmptyStore();
    /**
    * Cache of access config to reduce DB look-ups
    * @type {Object}
    */
    this.cache = {};
  }
  /**
  * Registers an access-checking plugin
  * @param {String} route The route for the check
  * @param {String} method The HTTP method
  * @param {Function} checkerFunc The validation function
  */
  registerPlugin(route, method, checkerFunc) {
    const m = method.toLowerCase();
    if(!this.plugins[m][route]) this.plugins[m][route] = [];
    this.plugins[m][route].push(checkerFunc);
  }
  /**
  * Runs all registered access checks for the current request
  * @param {ClientRequest} req
  * @return {Promise} Resolves when all checks have passed
  */
  async check(req) {
    if(req.auth.isSuper) return;

    // if(isCached(this.cache, req)) return;

    const plugins = this.plugins[req.method.toLowerCase()][req.baseUrl];

    if(!plugins) return;

    await Promise.all(plugins.map(async a => {
      try {
        await a(req);
      } catch(e) {
        req.details = e;
        throw AuthError.Authorise(req);
      }
    }));
    // cacheAccess(this.cache, req);
  }
}
/**
*
* @param {Object} cache The cache to use
* @param {ClientRequest} req The incoming request
* @return {Boolean} Whether the request has been previously cached
*/
function isCached(cache, { userId, url, method }) {
  try {
    return cache[userId][url][method.toLowerCase()];
  } catch(e) {
    return false;
  }
}
/**
* Caches the results for an access check
* @param {Object} cache The cache to use
* @param {ClientRequest} req The incoming request
*/
function cacheAccess(cache, { userId, url, method }) {
  if(!cache[userId]) cache[userId] = {};
  if(!cache[userId][url]) cache[userId][url] = {};
  cache[userId][url][method.toLowerCase()] = true;
}

module.exports = Access;
