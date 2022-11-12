import { App } from 'adapt-authoring-core';
import AuthUtils from './AuthUtils.js';
import jwt from 'jsonwebtoken';
import { promisify } from 'util';

/** @ignore */ const jwtSignPromise = promisify(jwt.sign);
/** @ignore */ const jwtVerifyPromise = promisify(jwt.verify);

/** @ignore */ const collectionName = 'authtokens';
/** @ignore */ const schemaName = 'authtoken';
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
  static getSignature(token) {
    return token.split('.')[2];
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
    const [auth, mongodb, users] = await App.instance.waitForModule('auth', 'mongodb', 'users');
    const [user] = await users.find({ email: token.sub });
    const authPlugin = auth.authentication.plugins[user.authType];
    if(!user) {
      throw App.instance.errors.UNAUTHENTICATED;
    }
    if(!user.isEnabled) {
      throw App.instance.errors.ACCOUNT_DISABLED;
    }
    if(!authPlugin) {
      throw App.instance.errors.UNKNOWN_AUTH_TYPE
        .setData({ authType: user.authType });
    }
    const userSchemaName = authPlugin.userSchema;
    await mongodb.update(collectionName, { signature: token.signature }, { $set: { usedAt: new Date() } });

    const scopes = await this.getScopesForUser(user);
    const isSuper = this.isSuper(scopes);
    Object.assign(req.auth, { isSuper, scopes, token, user, userSchemaName });
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
  static async generate(authType, userData, options = {}) {
    const [auth, jsonschema, mongodb] = await App.instance.waitForModule('auth', 'jsonschema', 'mongodb');
    const _id = mongodb.ObjectId.create().toString();
    const expiresIn = options.lifespan ?? AuthUtils.getConfig('defaultTokenLifespan');
    const token = await jwtSignPromise({ sub: userData.email, type: authType }, this.secret, {
      expiresIn,
      issuer: AuthUtils.getConfig('tokenIssuer')
    });
    const data = await jsonschema.validate(schemaName, {
      _id,
      authType,
      signature: this.getSignature(token),
      createdAt: new Date().toISOString(),
      userId: userData._id.toString()
    });
    await mongodb.insert(collectionName, data);
    auth.log('debug', 'AUTH_TOKEN_ISSUED', data.userId.toString(), data.authType, expiresIn);
    return token;
  }
  /**
   * Decodes a token
   * @param {String} token The token to decode
   * @return {Promise} Decoded token data
   */
  static async decode(token) {
    const tokenData = await jwtVerifyPromise(token, this.secret);

    tokenData.signature = this.getSignature(token);

    if(this.hasExpired(tokenData)) {
      throw App.instance.errors.AUTH_TOKEN_EXPIRED;
    }
    try { // verify we have a matching token in the DB
      await this.find({ signature: this.getSignature(token) });
    } catch(e) {
      throw App.instance.errors.UNAUTHENTICATED;
    }
    return tokenData;
  }
  /**
   * Retrieves an existing token
   * @param {Object} query
   * @param {Object} options
   * @param {Object} options.sanitise Whether the token data should be sanitised for returning via an API
   * @return {Promise} Resolves with the value from MongoDBModule#find
   */
  static async find(query, options = {}) {
    const [jsonschema, mongodb] = await App.instance.waitForModule('jsonschema', 'mongodb');
    const results = await mongodb.find(collectionName, query);

    if(!results.length) {
      throw App.instance.errors.NOT_FOUND
        .setData({ type: 'authtoken' });
    }
    if(!options.sanitise) {
      return results;
    }
    return Promise.all(results.map(r => jsonschema.sanitise(schemaName, r, { isInternal: true })));
  }
  /**
   * Invalidates an existing token
   * @param {Object} query Database query to identify tokens to be deleted
   * @return {Promise} Resolves with the value from MongoDBModule#delete
   */
  static async revoke(query) {
    const [auth, mongodb] = await App.instance.waitForModule('auth', 'mongodb');
    try {
      const results = await this.find(query);
      results.forEach(r => auth.log('debug', 'AUTH_TOKEN_REVOKED', r.userId, r.authType))
    } catch(e) {
      return; // just fail silently if token doesn't exist
    }
    return mongodb.getCollection(collectionName).deleteMany(query);
  }
}

export default AuthToken;