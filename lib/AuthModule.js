const { AbstractModule } = require('adapt-authoring-core');
const Access = require('./Access');
const Authentication = require('./Authentication');
const AuthToken = require('./AuthToken');
const AuthUtils = require('./AuthUtils');
const Permissions = require('./Permissions');
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
  }
  /**
   * Initialises the module
   * @return {Promise}
   */
  async init() {
    this.isEnabled = this.getConfig('isEnabled');
    if(!this.isEnabled) {
      if(this.app.config.getConfig('env.NODE_ENV') !== 'production') {
        this.log('info', 'auth disabled');
      } else {
        this.log('warn', 'cannot disable auth for production environments');
        this.isEnabled = true;
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
     * The permission-checking unit
     * @type {Permissions}
     */
    this.permissions = await Permissions.init(this);
    /**
     * The authentication unit
     * @type {Authentication}
     */
    this.authentication = await Authentication.init(this);
    /**
     * Reference to HTTP response status codes
     * @type {StatusCodes}
     */
    this.StatusCodes = server.StatusCodes;
  }
  /**
   * Locks a route to only users with the passed permissions scopes
   * @param {String} route The route
   * @param {String} method The HTTP method
   * @param {Array<String>} scopes Permissions scopes
   */
  secureRoute(route, method, scopes) {
    this.permissions.secureRoute(route, method, scopes);
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
   * Verifies the current request can access the requested resource
   * @param {ClientRequest} req
   * @param {ServerResponse} res
   * @param {Function} next
   */
  async handlerMiddleware(req, res, next) {
    try {
      await AuthUtils.initAuthData(req);

      const method = req.method.toLowerCase();
      const route = `${req.baseUrl}${req.route.path}`;
      const shortRoute = route.slice(0,route.lastIndexOf('/'));

      if(this.unsecuredRoutes[method][route] || this.unsecuredRoutes[method][shortRoute]) {
        return next();
      }
      if(this.isEnabled) {
        await AuthToken.initRequestData(req);
        await this.permissions.check(req);
        await this.access.check(req);
      }
      return next();
    } catch(e) {
      let userId;
      try {
        userId = req.auth.user._id;
      } catch(e2) {}
      this.log('debug', `blocked request to '${req.originalUrl}' (${e.statusCode}, ${userId})`);
      return next(e);
    }
  }
}

module.exports = AuthModule;
