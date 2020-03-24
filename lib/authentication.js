const { App } = require('adapt-authoring-core');
const AuthError = require('./authError');
const AuthUtils = require('./authUtils');

class Authentication {
  constructor() {
    /**
    * Registered authentication functions
    * @type {Array<Function>}
    */
    this.plugins = [];

    this.init();
  }
  async init() {
    const [ auth, server ] = await App.instance.waitForModule('auth', 'server');
    this.auth = auth;
    server.api.addRoute({
      route: '/authenticate',
      handlers: { post: this.authenticateHandler.bind(this) }
    });
    auth.unsecureRoute('/api/authenticate', 'post');

  }
  async authenticateHandler(req, res, next) {
    if(!req.auth.header) {
      return next(AuthError.Authenticate(`You must provide an authorisation token`));
    }
    try {
      const authData = await this.authenticate(req.auth);
      const user = await AuthUtils.findOrCreateUser(authData);
      const tokenData = {
        userId: user._id,
        scopes: await AuthUtils.getScopesForUser(user)
      };
      const tokenOpts = {
        expiresIn: this.getConfig('tokenLifespan'),
        issuer: 'adapt'
      };
      res.json({ token: await AuthUtils.generateToken(tokenData, tokenOpts) });
    } catch(e) {
      next(e);
    }
  }
  registerPlugin(authFunc) {
    this.plugins.push(authFunc);
  }
  async registerUser(data) {
    const [user] = await this.users.find(this.users.schemaName, this.users.collectionName, { email: data.email });
    if(user) {
      throw AuthError.Authenticate('Cannot create new user, user already exists');
    }
    return this.users.insert(this.users.schemaName, this.users.collectionName, data);
  }
  async authenticate(data) {
    let authData;
    const authsCopy = this.plugins.slice();
    const tryNextAuth = async () => {
      const a = authsCopy.shift();
      if(!a) {
        throw AuthError.Authenticate(`Couldn't authenticate request`);
      }
      const d = await a(data);
      if(d !== null) {
        authData = d;
        return;
      }
      await tryNextAuth();
    };
    await tryNextAuth(data);
    return authData;
  }
}

module.exports = Authentication;
