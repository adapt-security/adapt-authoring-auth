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
    auth.unsecureRoute('/api/auth/local', 'post');

  }
  async authenticateHandler(req, res, next) {
    try {
      const plugin = this.plugins[req.params.type];
      if(!plugin) {
        throw AuthError.Authenticate(`Could not authenticate, unknown auth type '${req.params.type}'`);
      }
      const authData = await plugin.authenticate(req);
      const user = await AuthUtils.findOrCreateUser(authData);
      const tokenData = {
        userId: user._id,
        scopes: await AuthUtils.getScopesForUser(user)
      };
      res.json({ token: await AuthUtils.generateToken(tokenData) });
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
