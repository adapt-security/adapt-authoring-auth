const AuthError = require('./authError');
const AuthUtils = require('./authUtils');

class Access {
  static async init() {
    return new Access();
  }
  constructor() {
    /**
    * The registered access checking functions, grouped by HTTP method & route
    * @type {RouteStore}
    * @example
    * {
    *   post: { "/api/test": () => true }
    * }
    * // i.e.
    * this.plugins.post["/api/test"]; // () => true;
  }
    */
    this.plugins = AuthUtils.createEmptyStore();
    this.cache = {};
  }
  registerPlugin(route, method, checkerFunc) {
    const m = method.toLowerCase();
    if(!this.plugins[m][route]) this.plugins[m][route] = [];
    this.plugins[m][route].push(checkerFunc);
  }
  async check(req) {
    // if(isCached(this.cache, req)) return;

    const plugins = this.plugins[req.method.toLowerCase()][req.baseUrl];

    if(!plugins) return;

    await Promise.all(plugins.map(async a => {
      try {
        await a(req);
      } catch(e) {
        req.details = e;
        throw AuthError.Authorise(req);
      }
    }));
    // cacheAccess(this.cache, req);
  }
}

function isCached(cache, { userId, url, method }) {
  try {
    return cache[userId][url][method.toLowerCase()];
  } catch(e) {
    return false;
  }
}
function cacheAccess(cache, { userId, url, method }) {
  if(!cache[userId]) cache[userId] = {};
  if(!cache[userId][url]) cache[userId][url] = {};
  cache[userId][url][method.toLowerCase()] = true;
}

module.exports = Access;
