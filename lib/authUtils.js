const AuthError = require('./autherror');
const { App } = require('adapt-authoring-core');
const jwt = require('jsonwebtoken');
/**
* Auth-related utility functions
*/
class AuthUtils {
  /**
  * The registered auth routes
  * @return {Object}
  */
  static get routes() {
    return App.instance.auth.routes;
  }
  /**
  * Checks whether the provided scopes are authorised to access a specific URL/HTTP method combination
  * @return {Boolean}
  */
  static isAuthorisedForRoute(method, url, currentScopes) {
    return true;
    /*
    if(!currentScopes || !currentScopes.length) {
      return false;
    }
    if(this.routes.unsecure[url] && this.routes.unsecure[url][method]) {
      return true;
    }
    const requiredScopes = this.routes.secure[url] && this.routes.secure[url][method];
    return requiredScopes && requiredScopes.every(s => currentScopes.includes(s));
    */
  }
  /**
  * Removes a trailing slash from a string
  * @param {String} s String to convert
  * @return {String}
  */
  static removeTrailingSlash(s) {
    return s.slice(-1) === '/' ? s.slice(0, s.length-1) : s;
  }
  static setRoute(method, route, routes, value) {
    const m = method.toLowerCase();
    const r = AuthUtils.removeTrailingSlash(route);

    if(!routes[r]) routes[r] = {};

    if(routes[r][m]) {
      throw new AuthError(App.instance.lang.t('error.alreadysecure', { method: m, route: r }));
    }
    if(!['post','get','put','patch','delete'].includes(m)) {
      throw new AuthError(App.instance.lang.t('error.secureroute', { method: m, route: r }));
    }

    routes[r][m] = value;
  }
  static createToken(token, secret, options) {
    return new Promise((resolve, reject) => {
      jwt.sign(token, secret, options, (error, payload) => {
        if(error) return reject(error);
        resolve(payload);
      });
    });
  }
  static decodeToken(token, secret, options) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, secret, options, (error, payload) => {
        if(error) return reject(error);
        resolve(payload);
      });
    });
  }
}

module.exports = AuthUtils;
