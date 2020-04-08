const { AbstractModule } = require('adapt-authoring-core');
const { AuthError } = require('adapt-authoring-auth');
/**
* Abstract module to be overridden by specific auth implementations
* @extends {AbstractAuthModule}
*/
class AbstractAuthModule extends AbstractModule {
  constructor(...args) {
    super(...args);
    this.init();
  }
  async init() {
    if(!this.name) {
      throw new Error('Must specify name');
    }
    this.auth = await this.app.waitForModule('auth', 'server');

    this.router = this.auth.router.createChildRouter(this.name);
    this.router.addRoute({
      route: '/',
      handlers: {
        post: (req, res, next) => {
          try {
            this.authenticate(req, res);
          } catch(e) {
            next(e);
          }
        }
      }
    }, ...this.routes);
    this.unsecureRoute('/', 'post');

    this.auth.authentication.registerPlugin(this.name, this);

    this.setReady();
  }
  unsecureRoute(route, method) {
    this.auth.unsecureRoute(`${this.router.path}${route}`, method);
  }
  async authenticate(req, res) {
    throw AuthError.Authenticate('must be implemented by subclass');
  }
}

module.exports = AbstractAuthModule;
