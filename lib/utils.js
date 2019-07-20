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
        id: {
          _id: '0000000000000000',
          firstName: 'Test',
          lastName: 'User'
        },
        scopes: [
          'read:users',
          'read:helloworld',
          'write:helloworld',
          'read:auth'
        ]
      };
      resolve();
    });
  }
  static authorise(req) {
    return new Promise((resolve, reject) => {
      const url = (req.baseUrl.slice(-1) === '/') ? req.baseUrl.slice(0, req.baseUrl.length-1) : req.baseUrl;
      const existing = req.auth.scopes;
      const required = this.routes[url] && this.routes[url][req.method.toLowerCase()];

      if(!existing || !required || !required.every(s => existing.includes(s))) {
        return reject(AuthError.Authorise({ method: req.method, url: req.baseUrl }));
      }
      resolve();
    });
  }
}

module.exports = Utils;
