const AuthError = require('./autherror');
const { App, Utils } = require('adapt-authoring-core');
/**
*
*/
class Utility {
  constructor(app, pkg) {
    this.app = app;
    this.app.auth = this;
    this.pkg = pkg;
    /**
    * @type {Array}
    */
    this.routes = {}
    const routes = {};
    Utils.defineGetter(this, 'routes', routes);
    /**
    * @type {Array}
    */
    this.scopes = [];
    const scopes = [];
    Utils.defineGetter(this, 'scopes', scopes);
    /**
    * @type {Function}
    */
    this.secureRoute = (route, method, scope) => {
      route = removeTrailingSlash(route);

      if(Array.isArray(scope)) {
        scopes.forEach(s => !scopes.includes(s) && scopes.push(scope));
      } else if(!scopes.includes(scope)) {
        scopes.push(scope);
      }
      if(!routes[route]) {
        routes[route] = {};
      }
      if(routes[route][method]) {
        return this.log(`Route ${method.toUpperCase()} '${route}' already secured`);
      }
      routes[route][method] = Array.isArray(scope) ? scope : [scope];
    }
  }
  log(m) {
    this.app.logger.log('warn', 'auth-utility', m);
  }
}

function removeTrailingSlash(s) {
  return (s.slice(-1) === '/') ? s.slice(0, s.length-1) : s;
}

module.exports = Utility;
/*
Add scopes
Add custom logic
Specify scopes for route/API

read
write
*/
