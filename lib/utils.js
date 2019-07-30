const AuthError = require('./autherror');
const { App } = require('adapt-authoring-core');
/**
*
*/
class Utils {
  static get routes() {
    return App.instance.auth.routes;
  }

  static authenticate(req) {
    return new Promise((resolve, reject) => {
      App.instance.logger.log('warn', 'auth-utils', 'Skipping authentication');
      const token = req.header('Authorization');
      if(!token) {
        // return reject(AuthError.Authenticate('no token provided'));
      }
      req.auth = {
        scopes: [
          'read:users',
          'read:helloworld',
          'write:helloworld',
          'read:auth'
        ]
        id: { userId: Date.now().toString().padStart(24, '0') },
      };
      resolve();
    });
  }

  static authorise(req) {
    return new Promise((resolve, reject) => {
      const method = req.method.toLowerCase();
      const url = `${req.baseUrl}${this.removeTrailingSlash(req.route.path)}`;
      const isAuthorised = this.isAuthorisedForRoute(method, url, req.auth.scopes);
      
      isAuthorised ? resolve() : reject(AuthError.Authorise({ method, url }));
    });
  }

  static isAuthorisedForRoute(method, url, currentScopes) {
    if(!currentScopes || !currentScopes.length) {
      return false;
    }
    if(this.routes.unsecure[url] && this.routes.unsecure[url][method]) {
      return true;
    }
    const requiredScopes = this.routes.secure[url] && this.routes.secure[url][method];
    return requiredScopes && requiredScopes.every(s => currentScopes.includes(s));
  }

  static removeTrailingSlash(s) {
    return (s.slice(-1) === '/') ? s.slice(0, s.length-1) : s;
  }
}

module.exports = Utils;
