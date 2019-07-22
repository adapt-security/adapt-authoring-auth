const AuthError = require('./autherror');
const AuthUtils = require('./utils');
const { App, Utils } = require('adapt-authoring-core');
/**
*
*/
class Utility {
  constructor(app, pkg) {
    this.app = app;
    this.app.auth = this;
    this.pkg = pkg;
    /**
    * @type {Array}
    */
    this.routes = {}
    const routes = {};
    Utils.defineGetter(this, 'routes', routes);
    /**
    * @type {Array}
    */
    this.scopes = [];
    const scopes = [];
    Utils.defineGetter(this, 'scopes', scopes);
    /**
    * @type {Function}
    */
    this.secureRoute = (route, method, scope) => {
      if(!Array.isArray(scope)) {
        scope = [scope];
      }
      method = method.toLowerCase();
      route = AuthUtils.removeTrailingSlash(route);

      if(!['post','get','put','patch','delete'].includes(method)) {
        return this.warn('secureroute', method, route);
      }
      scope.forEach(s => !scopes.includes(s) && scopes.push(s));

      if(!routes[route]) {
        routes[route] = {};
      }
      if(routes[route][method]) {
        return this.warn('alreadysecure', method, route);
      }
      routes[route][method] = scope;
    }
  }
  warn(key, method, route) {
    this.app.logger.log('warn', 'auth-utility', this.app.lang.t(`error.${key}`, { method, route }));
  }
}

module.exports = Utility;
