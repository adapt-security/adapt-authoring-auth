import { App } from 'adapt-authoring-core'
import apidefs from './apidefs.js'
import AuthToken from './AuthToken.js'
import AuthUtils from './AuthUtils.js'
import AbstractAuthModule from './AbstractAuthModule.js'
/**
 * Handles the authentication of incoming requests
 * @memberof auth
 */
class Authentication {
  /**
   * Creates and instanciates the class
   * @return {Promise} Resolves with the instance
   */
  static async init (auth) {
    const instance = new Authentication()
    await instance.init(auth)
    return instance
  }

  /** @constructor */
  constructor () {
    /**
     * Registered authentication plugins
     * @type {Object}
     */
    this.plugins = {}
  }

  /**
   * Initialises the instance
   * @param {AuthModule} auth The app auth module instance
   * @return {Promise}
   */
  async init (auth) {
    const jsonschema = await App.instance.waitForModule('jsonschema')
    jsonschema.registerSchemasHook.tap(this.registerSchema.bind(this))
    this.registerSchema()

    auth.router.addRoute({
      route: '/check',
      handlers: { get: this.checkHandler.bind(this) },
      meta: apidefs.check
    }, {
      route: '/disavow',
      handlers: { post: this.disavowHandler.bind(this) },
      meta: apidefs.disavow
    }, {
      route: '/generatetoken',
      handlers: { post: this.generateTokenHandler.bind(this) },
      meta: apidefs.generatetoken
    }, {
      route: '/tokens',
      handlers: { get: this.retrieveTokensHandler.bind(this) },
      meta: apidefs.tokens
    })
    auth.unsecureRoute(`${auth.router.path}/check`, 'get')
    auth.secureRoute(`${auth.router.path}/disavow`, 'post', ['disavow:auth'])
    auth.secureRoute(`${auth.router.path}/generatetoken`, 'post', ['generatetoken:auth'])
    auth.secureRoute(`${auth.router.path}/tokens`, 'get', ['read:me'])
  }

  /**
   * Registers a module to be used for authentication
   * @param {String} type Identifier for the module
   * @param {AbstractAuthModule} instance The auth module to register
   */
  registerPlugin (type, instance) {
    if (this.plugins[type]) {
      throw App.instance.errors.DUPL_AUTH_PLUGIN_REG
        .setData({ name: type })
    }
    if (!(instance instanceof AbstractAuthModule)) {
      throw App.instance.errors.AUTH_PLUGIN_INVALID_CLASS
        .setData({ name: type })
    }
    AuthUtils.log('debug', 'AUTH_PLUGIN', type)
    this.plugins[type] = instance
  }

  /**
   * Adds user schema extension
   */
  async registerSchema () {
    const jsonschema = await App.instance.waitForModule('jsonschema')
    jsonschema.extendSchema('user', 'authuser')
  }

  /**
   * Shortcut to authentication helper function
   * @param {String} authType Authentication type
   * @param {Object} userData Data to be inserted if user doesn't exist
   * @return {Promise}
   */
  async registerUser (authType, userData) {
    const authPlugin = this.plugins[authType]
    if (!authPlugin) {
      throw App.instance.errors.NOT_FOUND
        .setData({ id: authType, type: 'auth plugin' })
    }
    const users = await App.instance.waitForModule('users')
    return users.insert({ ...userData, authType }, { schemaName: authPlugin.userSchema })
  }

  /**
   * Deauthenticates a user
   * @param {object} query Token search query
   * @return {Promise}
   */
  async disavowUser (query) {
    if (!query.userId) {
      throw App.instance.errors.INVALID_PARAMS.setData({ params: ['userId'] })
    }
    const users = await App.instance.waitForModule('users')
    await users.find({ _id: query.userId })
    return AuthToken.revoke(query)
  }

  /**
   * Verifies the incoming request is correctly authenticated
   * @param {external:ExpressRequest} req
   * @param {external:ExpressResponse} res
   * @param {Function} next
   */
  async checkHandler (req, res, next) {
    try {
      if (!req.auth.header) {
        throw App.instance.errors.UNAUTHENTICATED
      }
      await AuthToken.initRequestData(req)

      res.json({
        scopes: req.auth.scopes,
        isSuper: req.auth.isSuper,
        user: {
          _id: req.auth.user._id,
          email: req.auth.user.email,
          firstName: req.auth.user.firstName,
          lastName: req.auth.user.lastName,
          roles: req.auth.user.roles
        }
      })
    } catch (e) {
      AuthUtils.log('debug', 'ACCESS_BLOCKED', e.code, req?.auth?.user?._id?.toString())
      res.sendError(e)
    }
  }

  /**
   * Verifies the incoming request is correctly authenticated
   * @param {external:ExpressRequest} req
   * @param {external:ExpressResponse} res
   * @param {Function} next
   */
  async disavowHandler (req, res, next) {
    try {
      const sessions = await App.instance.waitForModule('sessions')
      await this.disavowUser({ userId: req.auth.user._id, signature: req.auth.token.signature })
      await sessions.clearSession(req)
    } catch (e) {
      return next(e)
    }
    res.status(204).end()
  }

  /**
   * Handles token generation requests
   * @param {external:ExpressRequest} req
   * @param {external:ExpressResponse} res
   * @param {Function} next
   */
  async generateTokenHandler (req, res, next) {
    try {
      res.json({ token: await AuthToken.generate('manual', req.auth.user, { lifespan: req.body.lifespan }) })
    } catch (e) {
      return next(e)
    }
  }

  /**
   * Handles token retrieval requests
   * @param {external:ExpressRequest} req
   * @param {external:ExpressResponse} res
   * @param {Function} next
   */
  async retrieveTokensHandler (req, res, next) {
    try {
      res.json(await AuthToken.find({ userId: req.auth.user._id }, { sanitise: true }))
    } catch (e) {
      return next(e)
    }
  }
}

export default Authentication
