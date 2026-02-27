import { AbstractModule, Hook, readJson } from 'adapt-authoring-core'
import AuthToken from './AuthToken.js'
import { loadRouteConfig } from 'adapt-authoring-server'
/**
 * Abstract module to be overridden by specific auth implementations
 * @memberof auth
 * @extends {AbstractModule}
 */
class AbstractAuthModule extends AbstractModule {
  /**
   * Initialises the module
   * @return {Promise}
   */
  async init () {
    await this.setValues()
    const [auth, users] = await this.app.waitForModule('auth', 'users')
    /**
     * Cached reference to the auth module
     * @type {AuthModule}
     */
    this.auth = auth
    /**
     * Cached reference to the auth module
     * @type {UsersModule}
     */
    this.users = users
    if (!this.type) {
      throw this.app.errors.AUTH_TYPE_DEF_MISSING
    }
    /**
     * The router instance
     * @type {Router}
     */
    this.router = this.auth.router.createChildRouter(this.type)
    if (!this.routes) {
      this.routes = await this.getDefaultRoutes()
    }
    this.applyRoutes(this.routes)
    /**
     * Hook which is invoked when a new user is registered in the system
     * @type {Hook}
     */
    this.registerHook = new Hook({ mutable: true })

    this.auth.authentication.registerPlugin(this.type, this)
  }

  /**
   * Sets initial module values (set during initialisation), can be called by subclasses
   * @return {Promise}
   */
  async setValues () {
    /**
     * Identifier for the auth type
     * @type {String}
     */
    this.type = undefined
    /**
      * Custom endpoints for the auth type
      * @type {Array<Route>}
      */
    this.routes = undefined
    /**
      * Name of the schema to use when validating a user using this auth type
      * @type {String}
      */
    this.userSchema = 'user'

    const config = await loadRouteConfig(this.rootDir, this, {
      schema: 'authroutes',
      defaults: `${import.meta.dirname}/../default-routes.json`
    })
    if (config) {
      if (config.type) this.type = config.type
      this.routes = config.routes
    }
  }

  /**
   * Returns the default auth routes for this module.
   * Loads the route template from default-routes.json and resolves handler strings.
   * @return {Promise<Array>}
   */
  async getDefaultRoutes () {
    const template = await readJson(`${import.meta.dirname}/../default-routes.json`)
    return template.routes.map(r => {
      const resolved = { ...r, handlers: {} }
      for (const [method, handlerStr] of Object.entries(r.handlers)) {
        resolved.handlers[method] = this[handlerStr].bind(this)
      }
      return resolved
    })
  }

  /**
   * Adds routes to the router and applies auth permissions from route config
   * @param {Array} routes Array of route config objects with optional permissions field
   */
  applyRoutes (routes) {
    for (const route of routes) {
      this.router.addRoute(route)
      for (const [method, scopes] of Object.entries(route.permissions || {})) {
        if (scopes === null) {
          this.unsecureRoute(route.route, method)
        } else {
          this.secureRoute(route.route, method, scopes)
        }
      }
    }
  }

  /**
   * Locks a route to only users with the passed permissions scopes
   * @param {String} route The route
   * @param {String} method The HTTP method
   * @param {Array<String>} scopes Permissions scopes
   */
  secureRoute (route, method, scopes) {
    this.auth.secureRoute(`${this.router.path}${route}`, method, scopes)
  }

  /**
   * Removes auth checks from a single route {@link Auth#unsecureRoute}
   * @param {String} route The route
   * @param {String} method The HTTP method
   */
  unsecureRoute (route, method) {
    this.auth.unsecureRoute(`${this.router.path}${route}`, method)
  }

  /**
   * Registers a new user
   * @param {Object} data Data to be used for doc creation
   * @return {Promise} Resolves with the new user's data
   */
  async register (data) {
    return this.auth.authentication.registerUser(this.type, data)
  }

  /**
   * Sets the appropriate attributes to enable/disable user
   * @param {Object} user User DB document
   * @param {boolean} isEnabled Whether the user should be enabled
   * @return {Promise}
   */
  async setUserEnabled (user, isEnabled) {
    await this.users.update({ _id: user._id }, { isEnabled })
  }

  /**
   * A convenience function for accessing Authentication#disavowUser
   * @param {object} query Search query
   * @return {Promise}
   */
  async disavowUser (query) {
    return this.auth.authentication.disavowUser(query)
  }

  /**
   * Checks whether a user is allowed access to the APIs and performs any related auth type specific actions
   * @param {Object} user The user record
   * @param {external:ExpressRequest} req
   * @param {external:ExpressResponse} res
   * @return {Promise} Resolves on success
   */
  async authenticate (user, req, res) {
    throw this.app.errors.FUNC_NOT_OVERRIDDEN.setData({ name: `${this.constructor.name}#authenticate` })
  }

  /**
   * Handles authentication requests
   * @param {external:ExpressRequest} req
   * @param {external:ExpressResponse} res
   * @param {Function} next
   */
  async authenticateHandler (req, res, next) {
    const { email, persistSession } = req.body
    const [user] = await this.users.find({ email })
    if (!user) {
      return res.sendError(this.app.errors.INVALID_LOGIN_DETAILS)
    }
    try {
      await this.authenticate(user, req, res)

      if (req.session) {
        if (persistSession !== true) req.session.cookie.maxAge = null
        else this.log('debug', 'NEW_SESSION', user._id)

        req.session.token = await AuthToken.generate(this.type, user)
      }
      res.status(204).json()
    } catch (e) {
      this.log('debug', 'FAILED_LOGIN', !user ? 'INVALID_USER' : user?._id?.toString(), this.app.lang.translate(undefined, e))
      res.sendError(e)
    }
  }

  /**
   * Handles user enable/disable requests
   * @param {external:ExpressRequest} req
   * @param {external:ExpressResponse} res
   * @param {Function} next
   */
  async enableHandler (req, res, next) {
    try {
      const [user] = await this.users.find({ _id: req.body._id })
      const isEnable = req.url === '/enable'
      await this.setUserEnabled(user, isEnable)
      this.log('debug', isEnable ? 'USER_ENABLE' : 'USER_DISABLE', user._id, req?.auth?.user?._id?.toString())
      res.status(204).json()
    } catch (e) {
      return next(e)
    }
  }

  /**
   * Handles user registration requests
   * @param {external:ExpressRequest} req
   * @param {external:ExpressResponse} res
   * @param {Function} next
   */
  async registerHandler (req, res, next) {
    try {
      req.apiData = req.apiData ?? { modifying: true, data: req.body }
      await this.registerHook.invoke(req)
      const user = await this.register(req.body)
      this.log('debug', 'USER_REG', user._id, req?.auth?.user?._id?.toString())
      res.json(user)
    } catch (e) {
      return next(this.app.errors.USER_REG_FAILED.setData({ error: req.translate(e) }))
    }
  }
}

export default AbstractAuthModule
