import { AbstractModule, Hook } from 'adapt-authoring-core';
import AuthError from './AuthError.js';
/**
 * Abstract module to be overridden by specific auth implementations
 * @extends {AbstractModule}
 */
export default class AbstractAuthModule extends AbstractModule {
  /**
   * Initialises the module
   * @return {Promise}
   */
  async init() {
    await this.setValues();
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
            return next(e);
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
     this.registerHook = new Hook({ type: Hook.Types.Series, mutable: true });

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
   * @param {String} userId _id of the user to disavow
   * @return {Promise}
   */
   async disavowUser(userId) {
    return this.auth.authentication.disavowUser(this.type, userId);
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
  /**
   * Handles user registration requests
   * @param {ClientRequest} req
   * @param {ServerResponse} res
   * @param {Function} next
   */
   async registerHandler(req, res, next) {
    try {
      await this.registerHook.invoke(req);
      res.json(await this.register(req.body));
    } catch(e) {
      const e2 = new Error(`cannot register user, ${e.message}`);
      e2.statusCode = 400;
      return next(e2);
    }
  }
}