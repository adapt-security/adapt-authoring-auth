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

    const mongoStore = new MongoDBStore({
      collection: AuthUtils.getConfig('sessionsCollection'),
      uri: mongodb.connectionURI
    });
    server.expressApp.use(session({
      secret: AuthUtils.getConfig('sessionSecret'),
      cookie: { maxAge: AuthUtils.getConfig('sessionLifespan') },
      store: mongoStore,
      resave: false,
      saveUninitialized: true
    }));
    server.expressApp.use(passport.initialize());
    server.expressApp.use(passport.session());

    mongoStore.on('error', e => AuthUtils.log('error', e));
  }
}

module.exports = Passport;
