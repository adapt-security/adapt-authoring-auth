const AuthError = require('./authError');
const AuthUtils = require('./authUtils');
const { App } = require('adapt-authoring-core');
/**
* Handles checking user permissions for app endpoints
*/
class Permissions {
  /**
  * Creates and instanciates the class
  * @return {Promise} Resolves with the instance
  */
  static async init() {
    return new Permissions();
  }
  /** @constructor */
  constructor() {
    /**
    * Reference to all secured routes. Note that any route not explicitly secured will be denied by default.
    * @type {RouteStore}
    * @example
    * {
    *   post: { "/api/test": true }
    * }
    */
    this.routes = AuthUtils.createEmptyStore();
  }
  /**
  * Restricts access to a route/endpoint
  * @note All endpoints are blocked by default
  * @type {Function}
  * @param {String} route The route/endpoint to secure
  * @param {String} method HTTP method to block
  * @param {Array} scopes The scopes to restrict
  */
  secureRoute(route, method, scopes) {
    if(this.routes[method][route]) {
      return log('warn', this.t(`error.alreadysecure`, { method, route }));
    }
    this.routes[method.toLowerCase()][route] = scopes;
  }
  /**
  * Checks incoming request against stored permissions
  * @param {ClientRequest} req
  * @return {Promise} Resolves if request user passes checks
  */
  async check(req) {
    const scopes = this.routes[req.method.toLowerCase()][`${req.baseUrl}${req.path}`] || [];
    if(!req.auth.scopes.length || !scopes.length || !scopes.every(s => req.auth.scopes.includes(s))) {
      throw AuthError.Authorise({ method: req.method, url: `${req.baseUrl}${req.path}` });
    }
  }
}

async function log(...args) {
  const auth = await App.instance.waitForModule('auth');
  auth.log(...args);
}

module.exports = Permissions;
