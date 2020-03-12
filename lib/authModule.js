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
    const [ server, roles, users ] = await this.app.waitForModule('server', 'roles', 'users');

    server.api.addRoute({ route: '/authenticate', handlers: { post: this.authenticateHandler() } });
    this.unsecureRoute('/api/authenticate', 'post');

    server.requestHook.tap(this.handleRequest.bind(this));

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
  async handleRequest(req) {
    req.auth = {};
    if(req.get('Authorization')) {
      const [ type, value ] = req.get('Authorization').split(' ');
      req.auth.header = { type, value };
    }
    if(this.routes.unsecured[req.method.toLowerCase()][`${req.baseUrl}${req.path}`]) { // is unsecured
      return;
    }
    if(!req.auth.header) {
      throw AuthError.Authenticate(`You must provide an authorisation token`);
    }
    await this.processToken(req);
    await this.checkPermissions(req);
    await this.checkAccess(req);
  }
  processToken(req) {
    return new Promise((resolve, reject) => {
      if(req.auth.header.type !== 'Bearer') {
        return reject(AuthError.Authenticate(`Expected a Bearer token, got '${req.auth.header.type}'`));
      }
      jwt.verify(req.auth.header.value, this.getConfig('secret'), (error, tokenData) => {
        if(error) {
          return reject(AuthError.Authenticate(error.message));
        }
        if((tokenData.exp*1000) < Date.now()) {
          return reject(AuthError.Authenticate('Token has expired, you must authenticate again'));
        }
        this.app.waitForModule('mongodb').then(mongodb => {
          const signature = req.auth.header.value.split('.')[2];
          mongodb.find('authtokens', { signature }).then(([dbToken]) => {
            if(!dbToken) {
              return reject(AuthError.Authenticate(`Invalid token provided`));
            }
            Object.assign(req.auth, tokenData);
            console.log(req.auth);
            resolve();
          }, reject);
        }, reject);
      });
    });
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
    const authData = await this.runAuthenticators(data);
    const mongodb = await this.app.waitForModule('mongodb');
    let [user] = await this.users.find({ email: authData.email });
    const scopes = [];

    if(!user) {
      if(!authData.isNew) throw AuthError.Authenticate(`Couldn't authenticate user`);
      user = await this.registerUser(authData);
    }
    if(user.responsibilities.length) {
      const responsibilities = await this.responsibilities.find({
        $or: user.responsibilities.map(r => {
          Object.assign({}, { _id: mongodb.ObjectId.parse(r) });
        })
      });
      scopes.push(...responsibilities.reduce((memo, r) => {
        memo.push(...r.scopes);
        return memo;
      }, []));
    }
    return this.generateToken({ userId: user._id, scopes });
  }
  async runAuthenticators(data) {
    let authData;
    const authenticators = this.authenticators.slice();
    const tryNextAuth = async () => {
      const a = authenticators.shift();
      if(!a) {
        throw AuthError.Authenticate(`Couldn't authenticate request`);
      }
      const d = await a(data);
      if(d !== null) {
        authData = d;
        return;
      }
      await tryNextAuth();
    };
    await tryNextAuth(data);
    return authData;
  }
  generateToken(data) {
    return new Promise((resolve, reject) => {
      jwt.sign(data, this.getConfig('secret'), { expiresIn: this.getConfig('tokenLifespan'), issuer: 'adapt' }, (error, token) => {
        if(error) {
          return reject(error);
        }
        this.app.waitForModule('mongodb').then(db => {
          db.insert('authtokens', {
            signature: token.split('.')[2],
            createdAt: new Date().toISOString(),
            scopes: data.scopes
          }).then(() => resolve(token), reject);
        }, reject);
      });
    });
  }
}

module.exports = AuthModule;
