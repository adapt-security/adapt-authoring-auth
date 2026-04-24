import { AbstractModule } from 'adapt-authoring-core'
import Authentication from './Authentication.js'
import AuthToken from './AuthToken.js'
import MongoDBStore from 'connect-mongo'
import { createEmptyStore } from './utils/createEmptyStore.js'
import { initAuthData } from './utils/initAuthData.js'
import Permissions from './Permissions.js'
import session from 'express-session'
/**
 * Adds authentication + authorisation to the server
 * @memberof auth
 * @extends {AbstractModule}
 */
class AuthModule extends AbstractModule {
  /** @override */
  async init () {
    /**
     * All routes to ignore auth
     * @type {RouteStore}
     * @example
     * {
     *   post: { "/api/test": true }
     * }
     */
    this.unsecuredRoutes = createEmptyStore()
    /**
     * Whether auth should be enabled
     * @type {Boolean}
     */
    this.isEnabled = this.getConfig('isEnabled')

    if (!this.isEnabled) {
      if (this.app.getConfig('env.NODE_ENV') !== 'production') {
        this.log('info', 'auth disabled')
      } else {
        this.log('warn', 'cannot disable auth for production environments')
        this.isEnabled = true
      }
    }
    const [mongodb, server] = await this.app.waitForModule('mongodb', 'server')
    /**
     * Reference to the Express router
     * @type {Router}
     */
    this.router = server.api.createChildRouter('auth')

    /**
     * The permission-checking unit
     * @type {Permissions}
     */
    this.permissions = await Permissions.init(this)

    this.initSessions(mongodb, server)

    server.root.addHandlerMiddleware(this.rootMiddleware.bind(this))
    server.api.addHandlerMiddleware(this.apiMiddleware.bind(this))
    /**
     * The authentication unit
     * @type {Authentication}
     */
    this.authentication = await Authentication.init(this)
  }

  /**
   * Initialises session middleware on the Express app
   * @param {Object} mongodb The mongodb module instance
   * @param {Object} server The server module instance
   */
  initSessions (mongodb, server) {
    server.expressApp.use(
      session({
        name: 'adapt.user_session',
        resave: false,
        rolling: this.getConfig('sessionRolling'),
        saveUninitialized: true,
        secret: this.getConfig('sessionSecret'),
        unset: 'destroy',
        cookie: {
          maxAge: this.getConfig('sessionLifespan'),
          sameSite: this.getConfig('sessionSameSite'),
          secure: this.getConfig('sessionSecure')
        },
        store: MongoDBStore.create({
          client: mongodb.client,
          collection: this.getConfig('sessionCollection'),
          stringify: false
        })
      }),
      this.storeAuthHeader
    )
    this.secureRoute('/api/session/clear', 'post', ['clear:session'])
  }

  /**
   * Stores the session token as an auth header if none present
   * @param {external:ExpressRequest} req
   * @param {external:ExpressResponse} res
   * @param {function} next
   */
  storeAuthHeader (req, res, next) {
    const token = req?.session?.token
    if (token && !req.headers.Authorization) {
      req.headers.Authorization = `Bearer ${token}`
    }
    next()
  }

  /**
   * Locks a route to only users with the passed permissions scopes
   * @param {String} route The route
   * @param {String} method The HTTP method
   * @param {Array<String>} scopes Permissions scopes
   */
  secureRoute (route, method, scopes) {
    this.permissions.secureRoute(route, method, scopes)
  }

  /**
   * Allows unconditional access to a specific route
   * @type {Function}
   * @param {String} route The route/endpoint
   * @param {String} method HTTP method to allow
   */
  unsecureRoute (route, method) {
    this.unsecuredRoutes[method.toLowerCase()][route] = true
    this.log('warn', 'UNSECURED_ROUTE', method.toUpperCase(), route)
  }

  /**
   * Processes and parses incoming auth data
   * @param {external:ExpressRequest} req
   */
  async initAuthData (req) {
    await initAuthData(req)
    if (this.isEnabled) await AuthToken.initRequestData(req)
  }

  /**
   * Initialises auth data for root requests
   * @param {external:ExpressRequest} req
   * @param {external:ExpressResponse} res
   * @param {Function} next
   */
  rootMiddleware (req, res, next) {
    this.initAuthData(req).then(next, () => next())
  }

  /**
   * Initialises auth data for root requests
   * @param {external:ExpressRequest} req
   * @param {external:ExpressResponse} res
   * @param {Function} next
   */
  async apiMiddleware (req, res, next) {
    let initError
    try {
      await this.initAuthData(req)
    } catch (e) {
      initError = e
    }
    // Treat HEAD as GET: Express runs the GET handler chain for HEAD requests,
    // so auth rules must follow suit.
    const method = req.method === 'HEAD' ? 'get' : req.method.toLowerCase()
    const route = `${req.baseUrl}${req.route.path}`
    const shortRoute = route.slice(0, route.lastIndexOf('/'))
    const isUnsecured = this.unsecuredRoutes[method]?.[route] || this.unsecuredRoutes[method]?.[shortRoute]

    if (initError && !isUnsecured) {
      this.log('debug', 'BLOCK_REQUEST', req.originalUrl, initError.statusCode, req?.auth?.user?._id)
      return res.sendError(initError)
    }
    if (!isUnsecured) {
      await this.permissions.check(req)
    }
    next()
  }
}

export default AuthModule
