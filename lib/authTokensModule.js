const { AbstractApiModule } = require('adapt-authoring-api');
const { App } = require('adapt-authoring-core');
const AuthError = require('./authError');
const AuthUtils = require('./authUtils');
const jwt = require('jsonwebtoken');
const { promisify } = require('util');

const jwtSignPromise = promisify(jwt.sign);
const jwtVerifyPromise = promisify(jwt.verify);

class AuthTokensModule extends AbstractApiModule {
  /** @override */
  async setValues() {
    /** @ignore */ this.root = 'authtokens';
    /** @ignore */ this.schemaName = 'authtoken';
    /** @ignore */ this.collectionName = 'authtokens';
    /** @ignore */ this.routes = [
      {
        route: 'generate',
        handlers: { post: this.generateHandler.bind(this) }
      },
      {
        route: 'revoke',
        handlers: { post: this.revokeHandler.bind(this) }
      }
    ];
  }
  async generate(userData) {
    const tokenData = {
      user: {
        _id: userData._id,
        email: userData.email
      },
      scopes: await AuthUtils.getScopesForUser(userData)
    };
    const token = await jwtSignPromise(tokenData, AuthUtils.getConfig('tokenSecret'), { expiresIn: AuthUtils.getConfig('tokenLifespan'), issuer: this.getConfig('tokenIssuer') });
    this.insert();
    const mongodb = await App.instance.waitForModule('mongodb');
    await mongodb.insert('authtokens', {
      signature: token.split('.')[2],
      createdAt: new Date().toISOString(),
      userId: userData._id
    });
    return token;
  }
  async revoke() {
    // todo
  }
  async decode(token) {
    const tokenData = await jwtVerifyPromise(token, AuthUtils.getConfig('tokenSecret'));

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
  async generateHandler(req, res, next) {
    // todo
  }
  async revokeHandler(req, res, next) {
    // todo
  }
}

module.exports = AuthTokensModule;
