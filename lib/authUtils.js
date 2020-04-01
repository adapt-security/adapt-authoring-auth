const AuthError = require('./autherror');
const { App } = require('adapt-authoring-core');
/**
* Auth-related utility functions
*/
class AuthUtils {
  /**
  * Returns a generic empty object for mapping values to HTTP methods
  * @return {RouteStore}
  */
  static createEmptyStore() {
    /**
    * A key/value store linking API route/HTTP methods to values
    * @typedef {RouteStore}
    * @type {Object}
    * @property {Object} post Data relating to the post HTTP method
    * @property {Object} get Data relating to the get HTTP method
    * @property {Object} put Data relating to the put HTTP method
    * @property {Object} patch Data relating to the patch HTTP method
    * @property {Object} delete Data relating to the delete HTTP method
    */
    return {
      post: {},
      get: {},
      put: {},
      patch: {},
      delete: {}
    };
  }
  static async initAuthData(req) {
    req.auth = {};
    const authHeader = req.get('Authorization') || req.headers.Authorization;
    if(!authHeader) {
      return;
    }
    const [ type, value ] = authHeader.split(' ');
    req.auth.header = { type, value };
  }
  static getConfig(key) {
    return App.instance.config.get(`adapt-authoring-auth.${key}`);
  }
  static log(level, ...args) {
    return App.instance.logger.log(level, 'auth', ...args);
  }
}


module.exports = AuthUtils;
