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
    *   post: { "/api/test": () => true }
    * }
    * // i.e.
    * this.accessCheckers.post["/api/test"]; // () => true;
  }
    */
    this.accessCheckers = AuthUtils.createEmptyStore();
    /**
    * Reference to all secured & unsecured routes. Note that any route not explicitly secured will be denied by default.
    * @type {Object}
    * @property {RouteStore} secured The secured routes
    * @property {RouteStore} unsecured The unsecured routes (important: these are accessible by anyone).
    * @example
    * {
    *   post: { "/api/test": true }
    * }
    */
    this.routes = {
      secured: AuthUtils.createEmptyStore(),
      unsecured: AuthUtils.createEmptyStore()
    };
    this.init();
  }
  async init() {
    const [ server, roles, users ] = await this.app.waitForModule('server', 'roles', 'users');

    server.api.addHandlerMiddleware(this.handlerMiddleware.bind(this));

    server.api.addRoute({ route: '/authenticate', handlers: { post: this.authenticateHandler() } });
    this.unsecureRoute('/api/authenticate', 'post');

    this.StatusCodes = server.StatusCodes;
    this.roles = roles;
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
  async registerUser(data) {
    const [user] = await this.users.find(this.users.schemaName, this.users.collectionName, { email: data.email });
    if(user) {
      throw AuthError.Authenticate('Cannot create new user, user already exists');
    }
    return this.users.insert(this.users.schemaName, this.users.collectionName, data);
  }
  /**
  * Verifies the current request can access the requested resource
  * @param {ClientRequest} req
  * @return {Promise}
  */
  async handlerMiddleware(req, res, next) {
    AuthUtils.initAuthData(req);

    if(this.routes.unsecured[req.method.toLowerCase()][`${req.baseUrl}${req.path}`]) { // is unsecured
      return next();
    }
    if(!req.auth.header) {
      return next(AuthError.Authenticate(`no valid authorisation provided`));
    }
    if(req.auth.header.type !== 'Bearer') {
      return next(AuthError.Authenticate(`'${req.auth.header.type}' is not supported`));
    }
    try {
      await this.processToken(req);

      if(req.auth.scopes.length === 1 && req.auth.scopes[0] === '*:*') {
        return next(); // we have ourselves a super person
      }
      await this.checkPermissions(req);
      await this.checkAccess(req);
      next();
    } catch(e) {
      next(e);
    }
  }
  async processToken(req) {
    if(req.auth.header.type !== 'Bearer') {
      throw AuthError.Authenticate(`Expected a Bearer token, got '${req.auth.header.type}'`);
    }
    Object.assign(req.auth, await AuthUtils.decodeToken(req.auth.header.value, this.getConfig('secret')));
  }
  async checkPermissions(req) {
    const scopes = this.routes.secured[req.method.toLowerCase()][req.baseUrl];
    if(!scopes || !scopes.every(s => req.auth.scopes.includes(s))) {
      throw AuthError.Authorise({ method: req.method, url: `${req.baseUrl}${req.path}` });
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
  authenticateHandler() {
    return async (req, res, next) => {
      if(!req.auth.header) {
        return next(AuthError.Authenticate(`You must provide an authorisation token`));
      }
      try {
        res.json({ token: await this.authenticate(req.auth) });
      } catch(e) {
        next(e);
      }
    };
  }
  async authenticate(data) {
    const authData = await AuthUtils.runAuthenticators(this.authenticators, data);
    const user = await AuthUtils.findOrCreateUser(authData);
    const tokenData = {
      userId: user._id,
      scopes: await AuthUtils.getScopesForUser(user)
    };
    const tokenOpts = {
      expiresIn: this.getConfig('tokenLifespan'),
      issuer: 'adapt'
    };
    return AuthUtils.generateToken(tokenData, this.getConfig('secret'), tokenOpts);
  }
}

module.exports = AuthModule;
