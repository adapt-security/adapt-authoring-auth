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
    };
    /**
    * Registered authentication functions
    * @type {Array<Function>}
    */
    this.authenticators = [];
    /**
    * The registered access checking functions, grouped by HTTP method & route
    * @type {RouteStore}
    * @example
    * {
    *   post: {
    *     "/api/test": () => true
    *   }
    * }
    * // i.e.
    * this.accessCheckers.post["/api/test"]; // () => true;
  }
    */
    this.accessCheckers = createEmptyStore();
    /**
    * Reference to all secured & unsecured routes. Note that any route not explicitly secured will be denied by default.
    * @type {Object}
    * @property {RouteStore} secured The secured routes
    * @property {RouteStore} unsecured The unsecured routes (important: these are accessible by anyone).
    * @example
    * {
    *   post: {
    *     "/api/test": true
    *   }
    * }
    */
    this.routes = {
      secured: createEmptyStore(),
      unsecured: createEmptyStore()
    };
    this.init();
  }
  async init() {
    const [ server, responsibilities, users ] = await this.app.waitForModule('server', 'users');
    server.api.addRoute(
      { route: '/authenticate', handlers: { post: this.authenticate() } },
      { route: '/signup', handlers: { post: this.registerUser() } }
    );
    this.unsecureRoute('/api/authenticate', 'post');

    server.requestHook.tap(this.handleRequest.bind(this));

    this.StatusCodes = server.StatusCodes;
    this.responsibilities = responsibilities;
    this.users = users;

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
    await this.processToken(req);
    await this.checkPermissions(req);
    await this.checkAccess(req);
  }
  processToken(req) {
    return new Promise((resolve, reject) => {
      const authHeader = req.get('Authorization');
      if(!authHeader) {
        return reject(AuthError.Authenticate(`You must provide an authorisation token`));
      }
      jwt.verify(authHeader.replace('Bearer ', ''), this.getConfig('secret'), (error, tokenData) => {
        if(error) {
          return reject(AuthError.Authenticate(error.message));
        }
        req.user = tokenData;
        resolve();
      });
    });
  }
  async checkPermissions(req) {
    const scopes = this.routes.secured[req.method.toLowerCase()][req.baseUrl];
    if(!scopes || !scopes.every(s => req.user.scopes.includes(s))) {
      throw AuthError.Authorise(req);
    }
  }
  async checkAccess(req) {
    const accessCheckers = this.accessCheckers[req.method.toLowerCase()][req.baseUrl];
    if(!accessCheckers) {
      return;
    }
    const checkResults = await Promise.allSettled(accessCheckers.map(a => a(req)));
    if(!checkResults.some(r => r.status === 'fulfilled')) {
      throw AuthError.Authorise(req);
    }
  }
  authenticate() {
    return (req, res, next) => {
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
      res.json({ token: this.generateTokenForUser('12345678910') });
    }
  }
  registerUser() {
    return async (req, res, next) => {
      const db = this.app.waitForModule('mongodb');
      const user = this.users.find({ email: req.body.email });
    }
  }

  generateTokenForUser(userId) {
    return new Promise(async (resolve, reject) => {
      const db = await this.app.waitForModule('mongodb');
      const user = await this.users.find({ _id: userId });

      console.log(user);

      if(!user) {
        throw AuthError.Authenticate('User could not be authenticated');
      }
      const responsibilities = await this.responsibilities.find({ _id: { $OR: user.responsibilities } });
      const tokenData = {
        _id: user._id,
        scopes: responsibilities.reduce((memo, r) => { memo.push(...r.scopes); return memo; }, [])
      };
      jwt.sign(tokenData, this.getConfig('secret'), { issuer: 'test' }, (error, token) => {
        if(error) return reject(error);
        resolve(token);
      });
    });
  }
}

module.exports = AuthModule;
