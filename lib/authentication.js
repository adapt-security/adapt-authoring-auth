const _ = require('lodash');
const { App } = require('adapt-authoring-core');
const AuthError = require('./authError');
const AuthToken = require('./authToken');
const AuthUtils = require('./authUtils');
const AbstractAuthModule = require('./abstractAuthModule');
/**
 * Handles the authentication of incoming requests
 */
class Authentication {
  /**
   * Creates and instanciates the class
   * @return {Promise} Resolves with the instance
   */
  static async init(auth) {
    const instance = new Authentication();
    await instance.init(auth);
    return instance;
  }
  /** @constructor */
  constructor() {
    /**
     * Registered authentication plugins
     * @type {Object}
     */
    this.plugins = {};
  }
  /**
   * Initialises the instance
   * @param {AuthModule} auth The app auth module instance
   * @return {Promise}
   */
  async init(auth) {
    const jsonschema = await App.instance.waitForModule('jsonschema');

    jsonschema.extendSchema('user', 'authuser');

    auth.router.addRoute({
      route: '/check',
      handlers: { get: this.checkHandler.bind(this) }
    }, {
      route: '/disavow',
      handlers: { post: this.disavowHandler.bind(this) }
    });
    auth.unsecureRoute(`${auth.router.path}/check`, 'get');
    auth.permissions.secureRoute(`${auth.router.path}/disavow`, 'post', ['disavow:auth']);
  }
  /**
   * Registers a module to be used for authentication
   * @param {String} type Identifier for the module
   * @param {AbstractAuthModule} instance The auth module to register
   */
  registerPlugin(type, instance) {
    if(this.plugins[type]) {
      throw new Error(`Cannot register '${type}' auth plugin, name already in use`);
    }
    if(!(instance instanceof AbstractAuthModule)) {
      throw new Error(`Auth plugin '${type}' must extend AbstractAuthPlugin`);
    }
    AuthUtils.log('debug', `Registered '${type}' auth plugin`);
    this.plugins[type] = instance;
  }
  /**
   * Verifies the incoming request is correctly authenticated
   * @param {ClientRequest} req
   * @param {ServerResponse} res
   * @param {Function} next
   */
  async checkHandler(req, res, next) {
    try {
      if(!req.auth.header) {
        throw AuthError.Authenticate(`invalid authorisation data`);
      }
      await AuthToken.initRequestData(req);
      res.json(req.auth.token);
    } catch(e) {
      next(e);
    }
  }
  /**
   * Deauthenticates an authentication method for an existing user. Note that if a user is logged in using multiple authentication methods, the other methods will need to be disavowed separately.
   * @param {String} authType The type of authentication to disavow
   * @param {String} userId _id of the user to disavow
   * @return {Promise}
   */
  async disavowUser(authType, userId) {
    if(!authType || !userId) {
      throw new Error('Must provide authType and user userId');
    }
    return AuthToken.revoke({ userId, authType });
  }
  /**
   * Verifies the incoming request is correctly authenticated
   * @param {ClientRequest} req
   * @param {ServerResponse} res
   * @param {Function} next
   */
  async disavowHandler(req, res, next) {
    try {
      await this.disavowUser(req.auth.token.type, req.auth.user._id);
    } catch(e) {
      return next(e);
    }
    res.status(res.StatusCodes.Success.NoContent).end();
  }
}

module.exports = Authentication;
