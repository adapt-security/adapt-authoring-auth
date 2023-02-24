import { App } from 'adapt-authoring-core';
import AuthUtils from './AuthUtils.js';
import { pathToRegexp } from 'path-to-regexp';
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
  /**
   * Checks for routes which don't have valid permissions set, and logs a warning message (as these routes will not be accessible from the API)
   * @param {App} app The app instance
   * @return {Promise}
   */
  async checkRoutes(app) {
    const [auth, server] = await app.waitForModule('auth', 'server');

    if(!auth.getConfig('logMissingPermissions')) {
      return;
    }
    const missing = [];
    server.api.flattenRouters().forEach(router => {
      router.routes.forEach(routeConfig => {
        const route = `${router.path}${routeConfig.route}`;
        const shortRoute = route.slice(0,route.lastIndexOf('/'));
        Object.keys(routeConfig.handlers).forEach(method => {
          const isUnsecure = auth.unsecuredRoutes[method][route] || auth.unsecuredRoutes[method][shortRoute];
          const hasPermissions = !!this.getScopesForRoute(method, route);
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
    const m = method.toLowerCase();
    const re = pathToRegexp(route);
    if(this.routes[m][re]) {
      return log('warn', `Route ${m} '${route}' already secured`);
    }
    this.routes[m].push([re, scopes]);
  }
  /**
   * Returns the scopes needed for a specific route
   * @param {String} method HTTP method
   * @param {String} route The route to check
   * @returns {Array} the scopes required for route
   */
  getScopesForRoute(method, route) {
    for (const [re, scopes] of this.routes[method]) {
      if(re.test(route)) return scopes;
    }
  }
  /**
   * Checks incoming request against stored permissions
   * @param {external:ExpressRequest} req
   * @return {Promise} Resolves if request user passes checks
   */
  async check(req) {
    const route = `${req.baseUrl}${req.path.endsWith('/') ? req.path.slice(0, -1) : req.path}`;
    const userScopes = req.auth.scopes || [];
    const neededScopes = this.getScopesForRoute(req.method.toLowerCase(), route);
    if(!neededScopes) {
      log('warn', `blocked access to route with no permissions '${route}'`);
    }
    if(!neededScopes || !req.auth.isSuper && !neededScopes.every(s => userScopes.includes(s))) {
      throw App.instance.errors.UNAUTHORISED
        .setData({ method: req.method, url: route });
    }
  }
}
/** @ignore */
async function log(...args) {
  const auth = await App.instance.waitForModule('auth');
  auth.log(...args);
}

export default Permissions;