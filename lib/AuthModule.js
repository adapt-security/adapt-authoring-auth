import { AbstractModule } from 'adapt-authoring-core';
import Authentication from './Authentication.js';
import AuthToken from './AuthToken.js';
import AuthUtils from './AuthUtils.js';
import Permissions from './Permissions.js';
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
    /**
     * Whether auth should be enabled
     * @type {Boolean}
     */
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

    server.root.addHandlerMiddleware(this.rootMiddleware.bind(this));
    server.api.addHandlerMiddleware(this.apiMiddleware.bind(this));
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
   * Processes and parses incoming auth data
   * @param {ClientRequest} req
   */
   async initAuthData(req) {
    await AuthUtils.initAuthData(req);
    if(this.isEnabled) await AuthToken.initRequestData(req);
  }
  /**
   * Initialises auth data for root requests
   * @param {ClientRequest} req
   * @param {ServerResponse} res
   * @param {Function} next
   */
  rootMiddleware(req, res, next) {
    this.initAuthData(req).then(next, () => next());
  }
  /**
   * Initialises auth data for root requests
   * @param {ClientRequest} req
   * @param {ServerResponse} res
   * @param {Function} next
   */
  async apiMiddleware(req, res, next) {
    try {
      await this.initAuthData(req);
      next();
    } catch(e) {
      const method = req.method.toLowerCase();
      const route = `${req.baseUrl}${req.route.path}`;
      const shortRoute = route.slice(0,route.lastIndexOf('/'));
      const isUnsecured = this.unsecuredRoutes[method][route] || this.unsecuredRoutes[method][shortRoute];

      if(isUnsecured) {
        return next();
      }
      let userId;
      try {
        userId = req.auth.user._id;
      } catch(e) {} 
      // log error and stop the request here
      this.log('debug', `blocked request to '${req.originalUrl}' (${e.statusCode}, ${userId})`);
      res.sendError(e);
    }
  }
}

export default AuthModule;
