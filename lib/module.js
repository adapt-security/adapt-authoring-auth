const AuthUtils = require('./utils');
const { AbstractModule, DataStoreQuery, Responder } = require('adapt-authoring-core');
/**
* Adds authentication + authorisation to the server
* @extends {AbstractModule}
*/
class AuthModule extends AbstractModule {
  /** @override*/
  preload(app, resolve, reject) {
    const server = app.getModule('server');
    const r = server.api.createChildRouter('auth');

    app.dependencyloader.on('preload', () => {
      app.auth.scopes.forEach(s => {
        s = s.replace(':','.');
        r.addRoute({
          route: `/${s}`,
          handlers: { get: (req, res) => res.send(s) }
        });
        app.auth.secureRoute(`${r.path}/${s}`, 'get', ['read:auth']);
      });
    });
    server.requestHook.tap(this.handleRequest.bind(this));

    resolve();
  }
  /**
  * Verifies the current request can access the requested resource
  * @param {ClientRequest} req
  * @return {Promise}
  */
  handleRequest(req) {
    return AuthUtils.authenticate(req).then(() => AuthUtils.authorise(req));
  }
}

module.exports = AuthModule;
