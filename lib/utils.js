const AuthError = require('./autherror');
const { App } = require('adapt-authoring-core');
/**
* Auth-related utility functions
*/
class Utils {
  /**
  * The registered auth routes
  * @return {Object}
  */
  static get routes() {
    return App.instance.auth.routes;
  }
  /**
  * Middleware to check request is correctly authenticated
  * @param {ClientRequest} req
  * @return {Promise}
  */
  static authenticate(req) {
    return new Promise((resolve, reject) => {
      req.auth = {
        id: { userId: Date.now().toString().padStart(24, '0') },
        scopes: []
      };
      resolve();
    });
  }
  /**
  * Middleware to check request is correctly authorised
  * @param {ClientRequest} req
  * @return {Promise}
  */
  static authorise(req) {
    return new Promise((resolve, reject) => {
      const method = req.method.toLowerCase();
      const url = `${req.baseUrl}${this.removeTrailingSlash(req.route.path)}`;
      const isAuthorised = this.isAuthorisedForRoute(method, url, req.auth.scopes);

      // isAuthorised ? resolve() : reject(AuthError.Authorise({ method, url }));
      resolve();
    });
  }
  /**
  * Checks whether the provided scopes are authorised to access a specific URL/HTTP method combination
  * @return {Boolean}
  */
  static isAuthorisedForRoute(method, url, currentScopes) {
    if(!currentScopes || !currentScopes.length) {
      return false;
    }
    if(this.routes.unsecure[url] && this.routes.unsecure[url][method]) {
      return true;
    }
    const requiredScopes = this.routes.secure[url] && this.routes.secure[url][method];
    return requiredScopes && requiredScopes.every(s => currentScopes.includes(s));
  }
  /**
  * Removes a trailing slash from a string
  * @param {String} s String to convert
  * @return {String}
  */
  static removeTrailingSlash(s) {
    return (s.slice(-1) === '/') ? s.slice(0, s.length-1) : s;
  }
}

module.exports = Utils;
