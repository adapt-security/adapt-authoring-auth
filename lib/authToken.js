const { App } = require('adapt-authoring-core');
const AuthError = require('./authError');
const AuthUtils = require('./authUtils');
const jwt = require('jsonwebtoken');
const { promisify } = require('util');

const jwtSignPromise = promisify(jwt.sign);
const jwtVerifyPromise = promisify(jwt.verify);

const collectionName = 'authtokens';

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
  */
  static async initRequestData(req) {
    if(!req.auth.header) {
      throw AuthError.Authenticate(`no valid authorisation provided`);
    }
    if(req.auth.header.type !== 'Bearer') {
      throw AuthError.Authenticate(`expected a Bearer token, got '${req.auth.header.type}'`);
    }
    const tokenData = await this.decode(req.auth.header.value);
    const users = await App.instance.waitForModule('users');
    const [user] = await users.find({ email: tokenData.sub });
    if(!user) {
      throw AuthError.Authenticate(`couldn't verify user`);
    }
    Object.assign(req.auth, {
      user,
      token: tokenData,
      scopes: await this.getScopesForUser(user)
    });
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
  /**
  * Generates a new token
  * @param {Object} userData The user to be encoded
  * @return {Promise} Resolves with the token value
  */
  static async generate(userData) {
    const mongodb = await App.instance.waitForModule('mongodb');

    const id = mongodb.ObjectId.create();
    const token = await jwtSignPromise({ sub: userData.email, jti: id }, this.secret, {
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
