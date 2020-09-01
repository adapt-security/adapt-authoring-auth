const { AbstractModule } = require('adapt-authoring-core');
const AuthError = require('./authError');
/**
* Abstract module to be overridden by specific auth implementations
* @extends {AbstractAuthModule}
*/
class AbstractAuthModule extends AbstractModule {
  /** @override */
  constructor(...args) {
    super(...args);
    /**
    * Identifier for the auth type
    * @type {String}
    */
    this.type;
    /**
    * Custom endpoints for the auth type
    * @type {Array<Route>}
    */
    this.routes;

    this.init();
  }
  /**
  * Initialises the module
  * @return {Promise}
  */
  async init() {
    if(!this.type) {
      throw new Error('Must specify type');
    }
    /**
    * Cached reference to the auth module
    * @type {AuthModule}
    */
    this.auth = await this.app.waitForModule('auth');
    /**
    * The router instance
    * @type {Router}
    */
    this.router = this.auth.router.createChildRouter(this.type);
    this.router.addRoute({
      route: '/',
      handlers: {
        post: async (req, res, next) => {
          try {
            await this.authenticate(req, res);
          } catch(e) {
            next(e);
          }
        }
      }
    }, ...this.routes);
    this.unsecureRoute('/', 'post');

    this.auth.authentication.registerPlugin(this.type, this);
  }
  }
  /**
  * Removes auth checks from a single route {@link Auth#unsecureRoute}
  * @param {String} route The route
  * @param {String} method The HTTP method
  */
  unsecureRoute(route, method) {
    this.auth.unsecureRoute(`${this.router.path}${route}`, method);
  }
  /**
  * Checks whether a user is allowed access to the APIs
  * @param {ClientRequest} req
  * @param {ServerResponse} res
  * @return {Promise} Resolves on success
  */
  async authenticate(req, res) {
    throw AuthError.Authenticate('must be implemented by subclass');
  }
}

module.exports = AbstractAuthModule;
