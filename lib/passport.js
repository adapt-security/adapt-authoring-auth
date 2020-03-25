const { App } = require('adapt-authoring-core');
const AuthUtils = require('./authUtils');
const passport = require('passport');
const session = require('express-session');

const MongoDBStore = require('connect-mongodb-session')(session);

class Passport {
  constructor() {
    this.init();
  }
  async init() {
    const [ mongodb, server ] = await App.instance.waitForModule('mongodb', 'server');

    const secret = AuthUtils.getConfig('sessionSecret');
    const cookie = { maxAge: AuthUtils.getConfig('sessionLifespan') };
    const store = new MongoDBStore({ collection: AuthUtils.getConfig('sessionsCollection'), uri: mongodb.connectionURI });

    server.expressApp.use(session({ secret, cookie, store }));
    server.expressApp.use(passport.initialize());
    server.expressApp.use(passport.session());

    store.on('error', e => AuthUtils.log('error', e));
  }
}

module.exports = Passport;
