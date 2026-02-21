import { App } from 'adapt-authoring-core'
import { createEmptyStore } from './utils/createEmptyStore.js'
import { initAuthData } from './utils/initAuthData.js'
/**
 * Auth-related utility functions
 * @memberof auth
 */
class AuthUtils {
  /**
   * Returns a generic empty object for mapping values to HTTP methods
   * @return {RouteStore}
   * @deprecated Use named import { createEmptyStore } from 'adapt-authoring-auth' instead
   */
  static createEmptyStore () {
    return createEmptyStore()
  }

  /**
   * Adds auth data to the incoming request
   * @param {external:ExpressRequest} req
   * @return {Promise}
   * @deprecated Use named import { initAuthData } from 'adapt-authoring-auth' instead
   */
  static async initAuthData (req) {
    return initAuthData(req)
  }

  /**
   * Shortcut to retrieve auth config values
   * @param {String} key
   * @return {String}
   */
  static getConfig (key) {
    return App.instance.config.get(`adapt-authoring-auth.${key}`)
  }

  /**
   * Logs a message using the logger
   * @param {String} level The log level
   * @param {...*} args Other aruments
   */
  static log (level, ...args) {
    return App.instance.logger.log(level, 'auth', ...args)
  }
}

export default AuthUtils
