const AuthError = require('./autherror');
const { App } = require('adapt-authoring-core');
const jwt = require('jsonwebtoken');
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
  static initAuthData(req) {
    req.auth = {};
    if(req.get('Authorization')) {
      const [ type, value ] = req.get('Authorization').split(' ');
      req.auth.header = { type, value };
    }
  }
  static generateToken(data, secret, options) {
    return new Promise((resolve, reject) => {
      jwt.sign(data, secret, options, (error, token) => {
        if(error) {
          return reject(error);
        }
        App.instance.waitForModule('mongodb').then(db => {
          db.insert('authtokens', {
            signature: token.split('.')[2],
            createdAt: new Date().toISOString(),
            scopes: data.scopes
          }).then(() => resolve(token), reject);
        }, reject);
      });
    });
  }
  static decodeToken(token, secret) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, secret, (error, tokenData) => {
        if(error) {
          return reject(AuthError.Authenticate(error.message));
        }
        if(tokenData.exp*1000 < Date.now()) {
          return reject(AuthError.Authenticate('Token has expired, you must authenticate again'));
        }
        App.instance.waitForModule('mongodb').then(mongodb => {
          const signature = token.split('.')[2];
          mongodb.find('authtokens', { signature }).then(([dbToken]) => {
            if(!dbToken) {
              return reject(AuthError.Authenticate(`Invalid token provided`));
            }
            resolve(tokenData);
          }, reject);
        }, reject);
      });
    });
  }
  static async runAuthenticators(authenticators, data) {
    let authData;
    const authsCopy = authenticators.slice();
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
  static async findOrCreateUser(authData) {
    const users = await App.instance.waitForModule('users');
    const [user] = await users.find({ email: authData.email });
    if(user) {
      return user;
    }
    if(!authData.isNew) {
      throw AuthError.Authenticate(`Couldn't authenticate user`);
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
}

module.exports = AuthUtils;
