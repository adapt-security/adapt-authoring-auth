import { App } from 'adapt-authoring-core'
/**
 * Auth-related utility functions
 * @memberof auth
 */
class AuthUtils {
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
