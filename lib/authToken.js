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
  static async hasExpired(tokenData) {
    // * 1000 to get value as milliseconds
    return tokenData.exp*1000 < Date.now();
  }
  /**
  * Encodes a user into a token object for encoding
  * @param {Object} user User to be encoded
  * @return {Object} The data to be encoded into a token
  */
  static async tokenDataFromUser(user) {
    return {
      user: {
        _id: user._id,
        email: user.email
      },
      scopes: await AuthUtils.getScopesForUser(user)
    };
  }
  /**
  * Generates a new token
  * @param {Object} userData The user to be encoded
  * @return {Promise} Resolves with the token value
  */
  static async generate(userData) {
    const tokenData = this.tokenDataFromUser(userData);
    const token = await jwtSignPromise(tokenData, this.secret, {
      expiresIn: AuthUtils.getConfig('tokenLifespan'),
      issuer: AuthUtils.getConfig('tokenIssuer')
    });
    const mongodb = await App.instance.waitForModule('mongodb');
    await mongodb.insert(collectionName, {
      signature: token.split('.')[2],
      createdAt: new Date().toISOString(),
      userId: tokenData.user._id
    });
    return token;
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
}

module.exports = AuthToken;
