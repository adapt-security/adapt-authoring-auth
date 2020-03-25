const { AbstractModule } = require('adapt-authoring-core');
const Access = require('./access');
const Authentication = require('./authentication');
const AuthUtils = require('./authUtils');
const Permissions = require('./permissions');
/**
* Adds authentication + authorisation to the server
* @extends {AbstractModule}
*/
class AuthModule extends AbstractModule {
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

    if(!disable) {
      server.api.addHandlerMiddleware(this.handlerMiddleware.bind(this));
    }
    this.access = new Access(this.app);
    this.authentication = new Authentication(this.app);
    this.permissions = new Permissions(this.app);
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
  * @return {Promise}
  */
  async handlerMiddleware(req, res, next) {
    try {
      await AuthUtils.initAuthData(req);

      if(this.unsecuredRoutes[req.method.toLowerCase()][`${req.baseUrl}${req.path}`]) {
        return next();
      }
      await AuthUtils.initTokenData(req);

      await this.permissions.check(req);
      await this.access.check(req);
      next();
    } catch(e) {
      return next(e);
    }
  }
}

module.exports = AuthModule;
