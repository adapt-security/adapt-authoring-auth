const AuthError = require('./authError');
const AuthUtils = require('./authUtils');

class Permissions {
  constructor() {
    /**
    * Reference to all secured & unsecured routes. Note that any route not explicitly secured will be denied by default.
    * @type {Object}
    * @property {RouteStore} secured The secured routes
    * @property {RouteStore} unsecured The unsecured routes (important: these are accessible by anyone).
    * @example
    * {
    *   post: { "/api/test": true }
    * }
    */
    this.routes = {
      secured: AuthUtils.createEmptyStore(),
      unsecured: AuthUtils.createEmptyStore()
    };
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
    if(this.routes.secured[method][route]) {
      return this.log('warn', this.t(`error.alreadysecure`, { method, route }));
    }
    this.routes.secured[method.toLowerCase()][route] = scopes;
  }
  /**
  * Allows unconditional access to a specific route
  * @type {Function}
  * @param {String} route The route/endpoint
  * @param {String} method HTTP method to allow
  */
  unsecureRoute(route, method) {
    if(this.routes.secured[method][route]) {
      return this.log('warn', this.t(`error.alreadysecure`, { method, route }));
    }
    this.routes.unsecured[method.toLowerCase()][route] = true;
  }
  async check(req) {
    const scopes = this.routes.secured[req.method.toLowerCase()][req.baseUrl];
    if(!scopes || !scopes.every(s => req.auth.scopes.includes(s))) {
      throw AuthError.Authorise({ method: req.method, url: `${req.baseUrl}${req.path}` });
    }
  }
}

module.exports = Permissions;
