const AuthUtils = require('./utils');
const { AbstractUtility, App, Utils } = require('adapt-authoring-core');
/**
* Utility to handle authentication + authorisation
* @todo add custom logic
*/
class AuthUtility extends AbstractUtility {
  /**
  * @constructor
  * @param {App} app Main App instance
  * @param {Object} pkg Package.json data
  */
  constructor(app, pkg) {
    super(app, pkg);
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
        return warn('alreadysecure', method, route);
      }
      setRoute(method, route, routes.secure, scope);
    }
    /**
    * Allows unconditional access to a specific route
    * @type {Function}
    * @param {String} route The route/endpoint
    * @param {String} method HTTP method to allow
    */
    this.unsecureRoute = (route, method) => {
      setRoute(method, route, routes.unsecure, true);
    }
  }
}
/** @ignore*/
function setRoute(method, route, routes, value) {
  method = method.toLowerCase();
  route = AuthUtils.removeTrailingSlash(route);

  if(!['post','get','put','patch','delete'].includes(method)) {
    return warn('secureroute', method, route);
  }
  if(!routes[route]) {
    routes[route] = {};
  }
  routes[route][method] = value;
}
/** @ignore */
function warn(key, method, route) {
  App.instance.logger.log('warn', 'auth-utility', App.instance.lang.t(`error.${key}`, { method, route }));
}

module.exports = AuthUtility;
