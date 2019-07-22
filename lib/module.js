const AuthUtils = require('./utils');
const { DataStoreQuery, Module, Responder } = require('adapt-authoring-core');
/**
*
* @extends {Module}
*/
class Auth extends Module {
  /** @override*/
  preload(app, resolve, reject) {
    const server = app.getModule('server');
    const r = server.api.createChildRouter('auth');

    app.dependencyloader.on('preload', () => {
      app.auth.scopes.forEach(s => {
        s = s.replace(':','.');
        r.addRoute({
          route: `/${s}`,
          handlers: { get: () => res.send(key) }
        });
        app.auth.secureRoute(`${r.path}/${s}`, 'read', 'read:auth');
      });
      console.log(app.auth.routes);
    });
    server.requestHook.tap(this.handleRequest.bind(this));

    resolve();
  }
  handleRequest(req) {
    return AuthUtils.authenticate(req).then(() => AuthUtils.authorise(req));
  }
}

module.exports = Auth;
