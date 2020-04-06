const AuthError = require('./authError');
const AuthUtils = require('./authUtils');

class Permissions {
  static async init() {
    return new Permissions();
  }
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
      return this.log('warn', this.t(`error.alreadysecure`, { method, route }));
    }
    this.routes[method.toLowerCase()][route] = scopes;
  }
  async check(req) {
    const scopes = this.routes[req.method.toLowerCase()][req.baseUrl];
    if(!scopes || !scopes.every(s => req.auth.scopes.includes(s))) {
      throw AuthError.Authorise({ method: req.method, url: `${req.baseUrl}${req.path}` });
    }
  }
}

module.exports = Permissions;
