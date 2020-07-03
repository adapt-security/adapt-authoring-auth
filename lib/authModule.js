const { AbstractModule, Hook } = require('adapt-authoring-core');
const Access = require('./access');
const Authentication = require('./authentication');
const AuthToken = require('./authToken');
const AuthUtils = require('./authUtils');
const Permissions = require('./permissions');
/**
* Adds authentication + authorisation to the server
* @extends {AbstractModule}
*/
class AuthModule extends AbstractModule {
  /** @override */
  constructor(...args) {
    super(...args);
    /**
    * All routes to ignore auth
    * @type {RouteStore}
    * @example
    * {
    *   post: { "/api/test": true }
    * }
    */
    this.unsecuredRoutes = AuthUtils.createEmptyStore();
    this.init();
  }
  /**
  * Initialises the module
  * @return {Promise}
  */
  async init() {
    this.enabled = !this.getConfig('disable');
    if(!this.enabled) {
      if(this.app.config.getConfig('env.NODE_ENV') !== 'production') {
        this.log('info', 'auth disabled');
      } else {
        this.log('warn', 'cannot disable auth for production environments');
        this.enabled = true;
      }
    }
    const server = await this.app.waitForModule('server');
    /**
    * Reference to the Express router
    * @type {Router}
    */
    this.router = server.api.createChildRouter('auth');

    server.api.addHandlerMiddleware(this.handlerMiddleware.bind(this));
    /**
    * The access checker unit
    * @type {Access}
    */
    this.access = await Access.init(this);
    /**
    * The authentication unit
    * @type {Authentication}
    */
    this.authentication = await Authentication.init(this);
    /**
    * The permission-checking unit
    * @type {Permissions}
    */
    this.permissions = await Permissions.init(this);
    /**
    * Reference to HTTP response status codes
    * @type {StatusCodes}
    */
    this.StatusCodes = server.StatusCodes;

    this.disavowHook = new Hook();
    this.router.addRoute({
      route: '/disavow',
      handlers: { post: this.disavowHandler.bind(this) }
    });
    this.permissions.secureRoute(`${this.router.path}/disavow`, 'post', ['*:*']);

    this.setReady();
  }
  /**
  * Allows unconditional access to a specific route
  * @type {Function}
  * @param {String} route The route/endpoint
  * @param {String} method HTTP method to allow
  */
  unsecureRoute(route, method) {
    this.unsecuredRoutes[method.toLowerCase()][route] = true;
    this.log('debug', `route ${route} unsecured for HTTP method ${method.toUpperCase()}`);
  }
  /**
  * Retrieves or creates a new user from the provided details
  * @param {String} authType Authentication type
  * @param {String} email Email of user (must be unique)
  * @param {Object} userData Data to be inserted if user doesn't exist
  * @return {Promise}
  */
  async findOrCreateUser(authType, email, userData) {
    const users = await this.app.waitForModule('users');
    const [user] = await users.find({ email });

    if(!user) {
      return users.insert({ ...userData, authTypes: [authType] });
    }
    if(!user.authTypes.includes(authType)) {
      await users.update({ email }, { $push: { authTypes: authType } });
    }
    return user;
  }
  /**
  * Verifies the current request can access the requested resource
  * @param {ClientRequest} req
  * @param {ServerResponse} res
  * @param {Function} next
  */
  async handlerMiddleware(req, res, next) {
    try {
      await AuthUtils.initAuthData(req);

      if(this.unsecuredRoutes[req.method.toLowerCase()][`${req.baseUrl}${req.route.path}`]) {
        return next();
      }
      if(this.enabled) {
        await AuthToken.initRequestData(req);

        if(req.auth.isSuper) return next(); // super privileges

        await this.permissions.check(req);
        await this.access.check(req);
      }
      next();
    } catch(e) {
      return next(e);
    }
  }
  async disavowHandler(req, res, next) {
    // TODO
    await this.disavowHook.invoke(req);
    res.json({ tesing: 123 });
  }
}

module.exports = AuthModule;
