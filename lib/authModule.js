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

    this.init();
  }
  async init() {
    const server = await this.app.waitForModule('server');

    server.api.addRoute({ route: '/authenticate', handlers: { post: this.authenticate } });
    this.unsecureRoute('/api/authenticate', 'post');

    server.requestHook.tap(this.handleRequest.bind(this));

    this.StatusCodes = server.StatusCodes;

    this.setReady();
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
  registerAuthenticator(authFunc) {
    this.authenticators.push(authFunc);
  }
  registerAccessChecker(url, checkerFunc) {
    if(!this.accessCheckers[url]) {
      this.accessCheckers[url] = [];
    }
    this.accessCheckers[url].push(checkerFunc);
  }
  /**
  * Verifies the current request can access the requested resource
  * @param {ClientRequest} req
  * @return {Promise}
  */
  async handleRequest(req) {
    if(this.routes.unsecured[req.method.toLowerCase()][`${req.baseUrl}${req.path}`]) { // is unsecured
      return;
    }
    try {
      await this.processToken(req);
    } catch(e) {
      e.statusCode = this.StatusCodes.Error.Authenticate;
      throw e;
    }
    try {
      await this.checkPermissions(req);
      await this.checkAccess(req);
    } catch(e) {
      e.statusCode = this.StatusCodes.Error.Authorise;
      throw e;
    }
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
  async authenticate(req, res, next) {
    /*
    - Run through this.authenticators
      - Check if user can authenticate
        - Authenticator returns user identity
        - Create new user if none exists
      - Generate new API token
        - Store user identity, permissions scopes, access?
        - Store API token in DB
      - Return API token
    */
    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiIxMjM0NTY3ODkxMCIsInNjb3BlcyI6WyJyZWFkOmNvbnRlbnQiLCJyZWFkOnRhZ3MiXX0.TWnE3Md0sN1oaHc569ZPyIZ8illzMYOkuSJM5q9z_qs';
    res.json({ token });
  }
}

module.exports = AuthModule;
