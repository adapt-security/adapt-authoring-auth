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
      if(route.slice(-1) === '/') {
        route = route.slice(0, route.length-1);
      }
      console.log(route, scope);
      if(!scopes.includes(scope)) {
        Array.isArray(scope) ? scopes.push(...scope) : scopes.push(scope);
      }
      if(!routes[route]) {
        routes[route] = {};
      }
      if(!routes[route][method]) {
        routes[route][method] = Array.isArray(scope) ? scope : [scope];
      } else {
        this.app.logger.log('warn', 'auth-utility', `Route ${method.toUpperCase()} '${route}' already secured`);
      }
    }
  }
}

module.exports = Utility;
/*
Add scopes
Add custom logic
Specify scopes for route/API

read
write
*/
