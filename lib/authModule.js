const AuthError = require('./authError');
const AuthUtils = require('./authUtils');
const { AbstractModule } = require('adapt-authoring-core');
const jwt = require('jsonwebtoken');
/**
* Adds authentication + authorisation to the server
* @extends {AbstractModule}
*/
class AuthModule extends AbstractModule {
  constructor(...args) {
    super(...args);

    this.setReady();

    const createEmptyStore = () => {
      return {
        post: {},
        get: {},
        put: {},
        patch: {},
        delete: {}
      };
    };
    this.authenticators = [];
    this.accessCheckers = createEmptyStore();
    this.routes = { secured: createEmptyStore(), unsecured: createEmptyStore() };

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
    if(this.routes.secured[method][route]) {
      return this.log('warn', this.t(`error.alreadysecure`, { method, route }));
    }
    this.routes.secured[method.toLowerCase()][route] = scopes;
  }
  /**
  * Allows unconditional access to a specific route
  * @type {Function}
  * @param {String} route The route/endpoint
  * @param {String} method HTTP method to allow
  */
  unsecureRoute(route, method) {
    if(this.routes.secured[method][route]) {
      return this.log('warn', this.t(`error.alreadysecure`, { method, route }));
    }
    this.routes.unsecured[method.toLowerCase()][route] = true;
  }
  /**
  * Verifies the current request can access the requested resource
  * @param {ClientRequest} req
  * @return {Promise}
  */
  async handleRequest(req) {
    if(this.routes.unsecured[req.method.toLowerCase()][req.baseUrl]) { // is unsecured
      return;
    }
    await this.processToken(req);
    await this.checkPermissions(req);
    await this.checkAccess(req);
  }
  async processToken(req) {
    return new Promise((resolve, reject) => {
      const authHeader = req.get('Authorization');
      if(!authHeader) {
        reject(new Error(`This resource requires authorisation, none provided`));
      }
      jwt.verify(authHeader.replace('Bearer ', ''), this.getConfig('secret'), (error, tokenData) => {
        req.user = tokenData;
        resolve();
      });
    });
  }
  async checkPermissions(req) {
    const scopes = this.routes.secured[req.method.toLowerCase()][req.baseUrl];
    if(!scopes || !scopes.every(s => req.user.scopes.includes(s))) {
      throw new Error(`You don't have the correct permissions for this resource`);
    }
  }
  async checkAccess(req) {
    const accessCheckers = this.accessCheckers[req.method.toLowerCase()][req.baseUrl];
    if(!accessCheckers) {
      return;
    }
    const checkResults = await Promise.allSettled(accessCheckers.map(a => a(req)));
    if(!checkResults.some(r => r.status === 'fulfilled')) {
      throw new Error(`You don't have access to this resource`);
    }
  }
  registerAuthenticator() {

  }
  registerAccessChecker(url, checkerFunc) {
    if(!this.accessCheckers[url]) {
      this.accessCheckers[url] = [];
    }
    this.accessCheckers[url].push(checkerFunc);
  }
}

module.exports = AuthModule;
