import { AbstractModule, Hook } from 'adapt-authoring-core';
/**
 * Abstract module to be overridden by specific auth implementations
 * @extends {AbstractModule}
 */
class AbstractAuthModule extends AbstractModule {
  /**
   * Initialises the module
   * @return {Promise}
   */
  async init() {
    await this.setValues();
    if(!this.type) {
      throw this.app.errors.AUTH_TYPE_DEF_MISSING;
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
            res.sendError(e);
          }
        }
      }
    }, {
      route: '/register',
      handlers: { post: this.registerHandler.bind(this) }
    }, ...this.routes);

    this.secureRoute(`/register`, 'post', ['register:users']);
    this.unsecureRoute('/', 'post');
    /**
     * Hook which is invoked when a new user is registered in the system
     * @type {Hook}
     */
     this.registerHook = new Hook({ mutable: true });

    this.auth.authentication.registerPlugin(this.type, this);
  }
  /**
   * Sets initial module values (set during initialisation), can be called by subclasses
   * @return {Promise}
   */
  async setValues() {
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
     /**
      * Name of the schema to use when validating a user using this auth type
      * @type {String}
      */
     this.userSchema = 'user';
  }
  /**
   * Locks a route to only users with the passed permissions scopes
   * @param {String} route The route
   * @param {String} method The HTTP method
   * @param {Array<String>} scopes Permissions scopes
   */
  secureRoute(route, method, scopes) {
    this.auth.secureRoute(`${this.router.path}${route}`, method, scopes);
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
   * Registers a new user
   * @param {Object} data Data to be used for doc creation
   * @return {Promise} Resolves with the new user's data
   */
   async register(data) {
    const auth = await this.app.waitForModule('auth');
    return auth.authentication.registerUser(this.type, data);
  }
  /**
   * A convenience function for accessing Authentication#disavowUser
   * @param {external:express~Request} req
   * @param {Object} options
   * @return {Promise}
   */
   async disavowUser(req, options) {
    return this.auth.authentication.disavowUser(req, options);
  }
  /**
   * Checks whether a user is allowed access to the APIs
   * @param {external:express~Request} req
   * @param {external:express~Response} res
   * @return {Promise} Resolves on success
   */
  async authenticate(req, res) {
    throw this.app.errors.FUNC_NOT_OVERRIDDEN;
  }
  /**
   * Handles user registration requests
   * @param {external:express~Request} req
   * @param {external:express~Response} res
   * @param {Function} next
   */
   async registerHandler(req, res, next) {
    try {
      await this.registerHook.invoke(req);
      const user = await this.register(req.body);
      this.log('debug', 'USER_REG', user._id, req?.auth?.user?._id?.toString());
      res.json(user);
    } catch(e) {
      return next(this.app.errors.USER_REG_FAILED.setData({ error: e.message }));
    }
  }
}

export default AbstractAuthModule;