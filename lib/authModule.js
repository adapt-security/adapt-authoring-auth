const AuthError = require('./authError');
const AuthUtils = require('./authUtils');
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

    this.setReady();

    this.app.waitForModule('server').then(s => s.requestHook.tap(this.handleRequest.bind(this)));
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
    scopes.forEach(s => !this.scopes.includes(s) && this.scopes.push(s));

    if(this.routes.secure[route] && this.routes.secure[route][method]) {
      return this.log('warn', this.t(`error.alreadysecure`, { method, route }));
    }
    AuthUtils.setRoute(method, route, this.routes.secure, scopes);
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
    await this.authenticate(req);
    await this.authorise(req);
  }
  /**
  * Middleware to check request is correctly authenticated
  * @param {ClientRequest} req
  * @return {Promise}
  */
  async authenticate(req) {
    const tokenData = await AuthUtils.decodeToken(req.get('Authorization'), this.getConfig('secret'));
    req.auth = {
      id: { userId: Date.now().toString().padStart(24, '0') },
      scopes: []
    };
  }
  /**
  * Middleware to check request is correctly authorised
  * @param {ClientRequest} req
  * @return {Promise}
  */
  async authorise(req) {
    const method = req.method.toLowerCase();
    const url = `${req.baseUrl}${this.removeTrailingSlash(req.route.path)}`;

    if(!this.isAuthorisedForRoute(method, url, req.auth.scopes)) {
      throw AuthError.Authorise({ method, url });
    }
  }
}

module.exports = AuthModule;
