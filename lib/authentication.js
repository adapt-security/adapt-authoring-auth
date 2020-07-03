const _ = require('lodash');
const { App } = require('adapt-authoring-core');
const AuthError = require('./authError');
const AuthToken = require('./authToken');
const AuthUtils = require('./authUtils');
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
      handlers: { get: this.checkAuth.bind(this) }
    });
    auth.unsecureRoute(`${auth.router.path}/check`, 'get');
  }
  /**
  * Verifies the incoming request is correctly authenticated
  * @param {ClientRequest} req
  * @param {ServerResponse} res
  * @param {Function} next
  */
  async checkAuth(req, res, next) {
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
  * Registers a module to be used for authentication
  * @param {String} type Identifier for the module
  * @param {AbstractAuthModule} instance The auth module to register
  */
  registerPlugin(type, instance) {
    if(this.plugins[type]) {
      throw new Error(`Cannot register '${type}' auth plugin, name already in use`);
    }
    if(!_.isFunction(instance.authenticate)) {
      throw new Error(`Auth plugin '${type}' must implement an 'authenticate' function`);
    }
    AuthUtils.log('debug', `Registered '${type}' auth plugin`);
    this.plugins[type] = instance;
  }
}

module.exports = Authentication;
