const _ = require('lodash');
const { App } = require('adapt-authoring-core');
const AuthError = require('./authError');
const AuthUtils = require('./authUtils');

class Authentication {
  constructor() {
    /**
    * Registered authentication plugins
    * @type {Object}
    */
    this.plugins = {};

    this.init();
  }
  async init() {
    const [ auth, server ] = await App.instance.waitForModule('auth', 'server');
    this.auth = auth;
    this.router = server.api.createChildRouter('auth');
    this.router.addRoute({
      route: '/:type',
      handlers: { post: this.authenticateHandler.bind(this) }
    });
    auth.unsecureRoute('/api/auth/:type', 'post');
  }
  async authenticateHandler(req, res, next) {
    try {
      const plugin = this.plugins[req.params.type];
      if(!plugin) {
        throw AuthError.Authenticate(`unknown auth type '${req.params.type}'`);
      }
      plugin.authenticate(req, res, next);
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
