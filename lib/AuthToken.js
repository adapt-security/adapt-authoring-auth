import { App } from 'adapt-authoring-core';
import AuthUtils from './AuthUtils.js';
import jwt from 'jsonwebtoken';
import { promisify } from 'util';

/** @ignore */ const jwtSignPromise = promisify(jwt.sign);
/** @ignore */ const jwtVerifyPromise = promisify(jwt.verify);
/** Name of the database collection used for token storage */
/** @ignore */ const collectionName = 'authtokens';
/**
 * Utilities for dealing with JSON web tokens
 */
class AuthToken {
  /**
   * Retrieves the secret used during token generation
   * @type {String}
   */
  static get secret() {
    return AuthUtils.getConfig('tokenSecret');
  }
  /**
   * Determines whether the token has expired
   * @param {Object} tokenData The decoded token data
   * @return {Boolean}
   */
  static hasExpired(tokenData) {
    // * 1000 to get value as milliseconds
    return tokenData.exp*1000 < Date.now();
  }
  /**
   * Decodes and stores any token data on the Express ClientRequest object
   * @param {external:express~Request} req
   * @return {Promise}
   */
  static async initRequestData(req) {
    if(!req.auth.header) {
      throw App.instance.errors.MISSING_AUTH_HEADER;
    }
    if(req.auth.header.type !== 'Bearer') {
      throw App.instance.errors.AUTH_HEADER_UNSUPPORTED
        .setData({ type: req.auth.header.type });
    }
    const token = await this.decode(req.auth.header.value);
    const users = await App.instance.waitForModule('users');
    const [user] = await users.find({ email: token.sub });
    if(!user) {
      throw App.instance.errors.UNAUTHENTICATED;
    }
    if(!user.isEnabled) {
      throw App.instance.errors.ACCOUNT_DISABLED;
    }
    const scopes = await this.getScopesForUser(user);
    const isSuper = this.isSuper(scopes);
    Object.assign(req.auth, { user, token, scopes, isSuper });
  }
  /**
   * Generates a list of scopes which apply to the specified user
   * @param {Object} user The user document
   * @return {Promise} Resolves with an array of scopes
   */
  static async getScopesForUser(user) {
    if(!user.roles || !user.roles.length) {
      return [];
    }
    const roles = await App.instance.waitForModule('roles');
    const allRoles = await roles.find({});
    const userRoles = await allRoles.filter(r => user.roles.map(rId => rId.toString()).includes(r._id.toString()));
    return userRoles.reduce((memo, role) => {
      memo.push(...this.getScopesForRole(role.shortName, allRoles));
      return memo;
    }, []);
  }
  /**
   * Recursively builds a list of all scopes granted to a single role
   * @param {String} roleShortName the shortName value for the role
   * @param {Array} roles All system roles, passed for convenience
   * @return {Promise} Resolves with an array of scopes
   */
  static getScopesForRole(roleShortName, roles) {
    const role = roles.find(r => r.shortName === roleShortName);
    if(!role.extends) return role.scopes;
    return [...this.getScopesForRole(role.extends, roles), ...role.scopes];
  }
  /**
   * Utility function to check if a user has super privileges
   * @param {Array} scopes The user's permission scopes
   * @return {Promise}
   */
  static isSuper(scopes) {
    return scopes.length === 1 && scopes[0] === '*:*';
  }
  /**
   * Generates a new token
   * @param {String} authType Authentication type used
   * @param {Object} userData The user to be encoded
   * @param {Object} options
   * @param {string} options.lifespan Lifespan of the token
   * @return {Promise} Resolves with the token value
   */
  static async generate(authType, userData, { lifespan }) {
    const mongodb = await App.instance.waitForModule('mongodb');
    const _id = mongodb.ObjectId.create();
    const expiresIn = lifespan ?? AuthUtils.getConfig('defaultTokenLifespan');
    const token = await jwtSignPromise({ sub: userData.email, jti: _id, type: authType }, this.secret, {
      expiresIn,
      issuer: AuthUtils.getConfig('tokenIssuer')
    });
    await mongodb.insert(collectionName, {
      _id,
      authType,
      signature: token.split('.')[2],
      createdAt: new Date().toISOString(),
      userId: userData._id
    });
    auth.log('debug', 'AUTH_TOKEN_ISSUED', userData._id, authType, expiresIn);
    return token;
  }
  /**
   * Decodes a token
   * @param {String} token The token to decode
   * @return {Promise} Decoded token data
   */
  static async decode(token) {
    const tokenData = await jwtVerifyPromise(token, this.secret);

    if(this.hasExpired(tokenData)) {
      throw App.instance.errors.AUTH_TOKEN_EXPIRED;
    }
    try { // verify we have a matching token in the DB
      await this.find({ signature: token.split('.')[2] });
    } catch(e) {
      throw App.instance.errors.UNAUTHENTICATED;
    }
    return tokenData;
  }
  /**
   * Retrieves an existing token
   * @param {Object} query
   * @return {Promise} Resolves with the value from MongoDBModule#find
   */
  static async find(query) {
    const mongodb = await App.instance.waitForModule('mongodb');
    const [dbToken] = await mongodb.find(collectionName, query);

    if(!dbToken) {
      throw App.instance.errors.NOT_FOUND
        .setData({ type: 'authtoken' });
    }
    return dbToken;
  }
  /**
   * Invalidates an existing token
   * @param {Object} query Database query to identify tokens to be deleted
   * @return {Promise} Resolves with the value from MongoDBModule#delete
   */
  static async revoke(query) {
    try {
      const { userId, authType } = await this.find(query);
      auth.log('debug', 'AUTH_TOKEN_REVOKED', userId, authType);
    } catch(e) {
      return; // just fail silently if token doesn't exist
    }
    const mongodb = await App.instance.waitForModule('mongodb');
    return mongodb.getCollection(collectionName).deleteMany(query);
  }
}

export default AuthToken;