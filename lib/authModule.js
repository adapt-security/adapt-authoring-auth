const AuthUtils = require('./utils');
const { AbstractModule } = require('adapt-authoring-core');
/**
* Adds authentication + authorisation to the server
* @extends {AbstractModule}
*/
class AuthModule extends AbstractModule {
  constructor(...args) {
    super(...args);
    /**
    * The routes registered with the auth utility
    * @type {Object}
    */
    this.routes = { secure: {}, unsecure: {} };
    /**
    * The registered authorisation scopes
    * @type {Array}
    */
    this.scopes = [];

    this.init();
  }
  async init() {
    const server = await this.app.waitForModule('server');
    server.requestHook.tap(this.handleRequest.bind(this));
    this.setReady();
  }
  /**
  * Restricts access to a route/endpoint
  * @note All endpoints are blocked by default
  * @type {Function}
  * @param {String} route The route/endpoint to secure
  * @param {String} method HTTP method to block
  * @param {Array} scope The scope(s) to restrict
  */
  secureRoute(route, method, scope) {
    if(!Array.isArray(scope)) {
      scope = [scope];
    }
    scope.forEach(s => !this.scopes.includes(s) && this.scopes.push(s));

    if(this.routes.secure[route] && this.routes.secure[route][method]) {
      return this.log('warn', this.t(`error.alreadysecure`, { method, route }));
    }
    AuthUtils.setRoute(method, route, this.routes.secure, scope);
  }
  /**
  * Allows unconditional access to a specific route
  * @type {Function}
  * @param {String} route The route/endpoint
  * @param {String} method HTTP method to allow
  */
  unsecureRoute(route, method) {
    AuthUtils.setRoute(method, route, this.routes.unsecure, true);
  }
  /**
  * Verifies the current request can access the requested resource
  * @param {ClientRequest} req
  * @return {Promise}
  */
  async handleRequest(req) {
    await AuthUtils.authenticate(req);
    await AuthUtils.authorise(req);
  }
}

module.exports = AuthModule;
