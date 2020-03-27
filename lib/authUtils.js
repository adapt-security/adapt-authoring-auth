const AuthError = require('./autherror');
const { App } = require('adapt-authoring-core');
const jwt = require('jsonwebtoken');
const { promisify } = require('util');

const jwtSignPromise = promisify(jwt.sign);
const jwtVerifyPromise = promisify(jwt.verify);
/**
* Auth-related utility functions
*/
class AuthUtils {
  /**
  * Returns a generic empty object for mapping values to HTTP methods
  * @return {RouteStore}
  */
  static createEmptyStore() {
    /**
    * A key/value store linking API route/HTTP methods to values
    * @typedef {RouteStore}
    * @type {Object}
    * @property {Object} post Data relating to the post HTTP method
    * @property {Object} get Data relating to the get HTTP method
    * @property {Object} put Data relating to the put HTTP method
    * @property {Object} patch Data relating to the patch HTTP method
    * @property {Object} delete Data relating to the delete HTTP method
    */
    return {
      post: {},
      get: {},
      put: {},
      patch: {},
      delete: {}
    };
  }
  static async initAuthData(req) {
    req.auth = {};
    const authHeader = req.get('Authorization') || req.headers.Authorization;
    if(!authHeader) {
      return;
    }
    const [ type, value ] = authHeader.split(' ');
    req.auth.header = { type, value };
  }
  static async initTokenData(req) {
    if(!req.auth.header) {
      throw AuthError.Authenticate(`no valid authorisation provided`);
    }
    if(req.auth.header.type !== 'Bearer') {
      throw AuthError.Authenticate(`expected a Bearer token, got '${req.auth.header.type}'`);
    }
    Object.assign(req.auth, await this.decodeToken(req.auth.header.value));
  }
  static async generateToken(userData) {
    const tokenData = {
      user: {
        _id: userData._id,
        email: userData.email
      },
      scopes: await this.getScopesForUser(userData)
    };
    const token = await jwtSignPromise(tokenData, this.getConfig('tokenSecret'), { expiresIn: this.getConfig('tokenLifespan'), issuer: this.getConfig('tokenIssuer') });
    const mongodb = await App.instance.waitForModule('mongodb');
    await mongodb.insert('authtokens', {
      signature: token.split('.')[2],
      createdAt: new Date().toISOString(),
      scopes: tokenData.scopes
    });
    return token;
  }
  static async decodeToken(token) {
    let tokenData;
    try {
      tokenData = await jwtVerifyPromise(token, this.getConfig('tokenSecret'));
    } catch(e) {
      throw AuthError.Authenticate(e.message);
    }
    if(tokenData.exp*1000 < Date.now()) {
      throw AuthError.Authenticate('token has expired, you must authenticate again');
    }
    const signature = token.split('.')[2];
    const mongodb = await App.instance.waitForModule('mongodb');
    const [dbToken] = await mongodb.find('authtokens', { signature });

    if(!dbToken) {
      throw AuthError.Authenticate(`invalid token provided`);
    }
    return tokenData;
  }
  static async findOrCreateUser(data) {
    const users = await App.instance.waitForModule('users');
    const [user] = await users.find({ email: data.email });
    return user || users.insert(data);
  }
  static async getScopesForUser(user) {
    if(!user.roles.length) {
      return [];
    }
    const [mongodb, roles] = await App.instance.waitForModule('mongodb', 'roles');
    const userRoles = await roles.find({
      $or: user.roles.map(r => Object.assign({}, { _id: mongodb.ObjectId.parse(r) }))
    });
    return userRoles.reduce((memo, role) => {
      memo.push(...role.scopes);
      return memo;
    }, []);
  }
  static getConfig(key) {
    return App.instance.config.get(`adapt-authoring-auth.${key}`);
  }
  static log(level, ...args) {
    return App.instance.logger.log(level, 'adapt-authoring-auth', ...args);
  }
}


module.exports = AuthUtils;
