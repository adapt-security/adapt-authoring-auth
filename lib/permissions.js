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

    App.instance.onReady().then(this.checkRoutes.bind(this));
  }
  async checkRoutes(app) {
    const [auth, server] = await app.waitForModule('auth', 'server');

    if(!auth.getConfig('logMissingPermissions')) {
      return;
    }
    const missing = [];
    server.api.flattenRouters().forEach(router => {
      router.routes.forEach(routeConfig => {
        const route = `${router.path}${routeConfig.route}`;
        Object.keys(routeConfig.handlers).forEach(method => {
          const isUnsecure = auth.unsecuredRoutes[method][route];
          const hasPermissions = this.routes[method][route] || this.routes[method][route.slice(0,route.lastIndexOf('/'))];
          if(!isUnsecure && !hasPermissions) missing.push({ route, method });
        });
      });
    });
    missing.forEach(({ route, method }) => log('warn', `no permissions specified for ${method.toUpperCase()} ${route}`));
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
      return log('warn', App.instance.lang.t(`error.alreadysecure`, { method, route }));
    }
    this.routes[method.toLowerCase()][route] = scopes;
  }
  /**
  * Checks incoming request against stored permissions
  * @param {ClientRequest} req
  * @return {Promise} Resolves if request user passes checks
  */
  async check(req) {
    const routes = this.routes[req.method.toLowerCase()];
    const route = `${req.baseUrl}${req.path}`;
    const routeNoParam = route.slice(0, route.lastIndexOf('/'));
    const userScopes = req.auth.scopes || [];
    const neededScopes = routes[route] || routes[routeNoParam];
    if(!neededScopes) {
      log('warn', `blocked access to route with no permissions '${route}'`);
    }
    if(!neededScopes || !req.auth.isSuper && !neededScopes.every(s => userScopes.includes(s))) {
      throw AuthError.Authorise({ method: req.method, url: route });
    }
  }
}

async function log(...args) {
  const auth = await App.instance.waitForModule('auth');
  auth.log(...args);
}

module.exports = Permissions;
