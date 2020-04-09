const { AbstractModule } = require('adapt-authoring-core');
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
    let disable = this.getConfig('disable');
    if(disable) {
      if(this.app.config.getConfig('env.NODE_ENV') !== 'production') {
        this.log('info', 'Auth disabled');
      } else {
        this.log('warn', 'Cannot disable auth for production environments');
        disable = false;
      }
    }
    const server = await this.app.waitForModule('server');
    /**
    * Reference to the Express router
    * @type {Router}
    */
    this.router = server.api.createChildRouter('auth');

    if(!disable) {
      server.api.addHandlerMiddleware(this.handlerMiddleware.bind(this));
    }
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
      await AuthToken.initRequestData(req);

      await this.permissions.check(req);
      await this.access.check(req);
      next();
    } catch(e) {
      return next(e);
    }
  }
}

module.exports = AuthModule;
