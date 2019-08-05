const AuthError = require('./autherror');
const AuthUtils = require('./utils');
const { App, Utils } = require('adapt-authoring-core');
/**
* Utility to handle authentication + authorisation
* @todo add custom logic
*/
class AuthUtility {
  constructor(app, pkg) {
    this.app = app;
    this.app.auth = this;
    this.pkg = pkg;
    /**
    * The routes registered with the auth utility
    * @type {Object}
    */
    this.routes = {};
    const routes = { secure: {}, unsecure: {} };
    Utils.defineGetter(this, 'routes', routes);
    /**
    * The registered authorisation scopes
    * @type {Array}
    */
    this.scopes = [];
    const scopes = [];
    Utils.defineGetter(this, 'scopes', scopes);
    /**
    * Restricts access to a route/endpoint
    * @note All endpoints are blocked by default
    * @type {Function}
    * @param {String} route The route/endpoint to secure
    * @param {String} method HTTP method to block
    * @param {Array} scope The scope(s) to restrict
    */
    this.secureRoute = (route, method, scope) => {
      if(!Array.isArray(scope)) {
        scope = [scope];
      }
      scope.forEach(s => !scopes.includes(s) && scopes.push(s));

      if(routes.secure[route] && routes.secure[route][method]) {
        return this.warn('alreadysecure', method, route);
      }
      this.setRoute(method, route, routes.secure, scope);
    }
    /**
    * Allows unconditional access to a specific route
    * @type {Function}
    * @param {String} route The route/endpoint
    * @param {String} method HTTP method to allow
    */
    this.unsecureRoute = (route, method) => {
      this.setRoute(method, route, routes.unsecure, true);
    }
  }
  setRoute(method, route, routes, value) {
    method = method.toLowerCase();
    route = AuthUtils.removeTrailingSlash(route);

    if(!['post','get','put','patch','delete'].includes(method)) {
      return this.warn('secureroute', method, route);
    }
    if(!routes[route]) {
      routes[route] = {};
    }
    routes[route][method] = value;
  }
  warn(key, method, route) {
    this.app.logger.log('warn', 'auth-utility', this.app.lang.t(`error.${key}`, { method, route }));
  }
}

module.exports = AuthUtility;
