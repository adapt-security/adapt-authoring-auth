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
    if(!req.get('Authorization')) {
      throw AuthError.Authenticate(`no valid authorisation provided`);
    }
    const [ type, value ] = req.get('Authorization').split(' ');
    req.auth.header = { type, value };
    Object.assign(req.auth, await this.tokenFromReq(req));
  }
  static async tokenFromReq(req) {
    if(!req.auth.header) {
      throw AuthError.Authenticate(`no valid authorisation provided`);
    }
    if(req.auth.header.type !== 'Bearer') {
      throw AuthError.Authenticate(`expected a Bearer token, got '${req.auth.header.type}'`);
    }
    return this.decodeToken(req.auth.header.value);
  }
  static async generateToken(data, options) {
    const secret = App.instance.config.get('adapt-authoring-auth.secret');
    const token = await jwtSignPromise(data, secret, options);
    const mongodb = await App.instance.waitForModule('mongodb');
    await mongodb.insert('authtokens', {
      signature: token.split('.')[2],
      createdAt: new Date().toISOString(),
      scopes: data.scopes
    });
    return token;
  }
  static async decodeToken(token) {
    let tokenData;
    try {
      tokenData = await jwtVerifyPromise(token, this.getConfig('secret'));
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
  static async findOrCreateUser(authData) {
    const users = await App.instance.waitForModule('users');
    const [user] = await users.find({ email: authData.email });
    if(user) {
      return user;
    }
    if(!authData.isNew) {
      throw AuthError.Authenticate(`couldn't authenticate user`);
    }
    return this.registerUser(authData);
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
}


module.exports = AuthUtils;
