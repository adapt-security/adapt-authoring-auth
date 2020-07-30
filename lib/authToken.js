const { App } = require('adapt-authoring-core');
const AuthError = require('./authError');
const AuthUtils = require('./authUtils');
const jwt = require('jsonwebtoken');
const { promisify } = require('util');

/** @ignore */ const jwtSignPromise = promisify(jwt.sign);
/** @ignore */ const jwtVerifyPromise = promisify(jwt.verify);
/**
* Name of the database collection used for token storage
*/
const collectionName = 'authtokens';
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
  * @param {ClientRequest} req
  * @return {Promise}
  */
  static async initRequestData(req) {
    if(!req.auth.header) {
      throw AuthError.Authenticate(`no valid authorisation provided`);
    }
    if(req.auth.header.type !== 'Bearer') {
      throw AuthError.Authenticate(`expected a Bearer token, got '${req.auth.header.type}'`);
    }
    const token = await this.decode(req.auth.header.value);
    const users = await App.instance.waitForModule('users');
    const [user] = await users.find({ email: token.sub });
    if(!user) {
      throw AuthError.Authenticate(`couldn't verify user`);
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
  static getScopesForRole(roleShortName, roles) {
    const role = roles.find(r => r.shortName === roleShortName);
    if(!role.extends) return role.scopes;
    return [...this.getScopesForRole(role.extends, roles), ...role.scopes];
  }
  static isSuper(scopes) {
    return scopes.length === 1 && scopes[0] === '*:*';
  }
  /**
  * Generates a new token
  * @param {String} authType Authentication type used
  * @param {Object} userData The user to be encoded
  * @return {Promise} Resolves with the token value
  */
  static async generate(authType, userData) {
    const mongodb = await App.instance.waitForModule('mongodb');
    const id = mongodb.ObjectId.create();
    const token = await jwtSignPromise({ sub: userData.email, jti: id, type: authType }, this.secret, {
      expiresIn: AuthUtils.getConfig('tokenLifespan'),
      issuer: AuthUtils.getConfig('tokenIssuer')
    });
    await mongodb.insert(collectionName, {
      _id: id,
      signature: token.split('.')[2],
      createdAt: new Date().toISOString(),
      userId: userData._id
    });
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
      throw AuthError.Authenticate('token has expired, you must authenticate again');
    }
    // verify we have a matching token in the DB
    await this.find({ signature: token.split('.')[2] });

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
      throw AuthError.Authenticate(`no matching token found`);
    }
    return dbToken;
  }
  /**
  * Invalidates an existing token
  * @param {String} _id The ObjectID of the token to revoke
  * @return {Promise} Resolves with the value from MongoDBModule#delete
  */
  static async revoke(_id) {
    await this.find({ _id });
    const mongodb = await App.instance.waitForModule('mongodb');
    return mongodb.delete(collectionName, { _id });
  }
}

module.exports = AuthToken;
