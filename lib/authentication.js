const _ = require('lodash');
const { App } = require('adapt-authoring-core');
const AuthError = require('./authError');
const AuthToken = require('./authToken');
const AuthUtils = require('./authUtils');

class Authentication {
  static async init(auth) {
    const instance = new Authentication();
    await instance.init(auth);
    return instance;
  }
  constructor() {
    /**
    * Registered authentication plugins
    * @type {Object}
    */
    this.plugins = {};
  }
  async init(auth) {
    const server = await App.instance.waitForModule('server');

    auth.router.addRoute({
      route: '/check',
      handlers: { get: this.decodeToken.bind(this) }
    });
    auth.unsecureRoute(`${auth.router.path}/check`, 'get');
  }
  async decodeToken(req, res, next) {
    try {
      if(!req.auth.header) {
        throw AuthError.Authenticate(`invalid authorisation data`);
      }
      res.json(await AuthToken.decode(req.auth.header.value));
    } catch(e) {
      next(e);
    }
  }
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
