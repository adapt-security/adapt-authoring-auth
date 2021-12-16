/**
 * Error for authentication & authorisation
 * @extends {Error}
 */
export default class AuthError extends Error {
  /**
   * Creates a new authentication error
   * @param {String} msg The error message
   * @param {Number} statusCode The HTTP status code
   * @return {AuthError}
   */
  static Authenticate(msg, statusCode = 401) {
    return new AuthError(`You couldn't be authenticated with the API, ${msg}`, statusCode);
  }
  /**
   * Creates a new authorisation error
   * @param {Object} data Data to be formatted into an error
   * @param {Number} statusCode The HTTP status code
   * @return {AuthError}
   */
  static Authorise(data, statusCode = 403) {
    return new AuthError(`You don't have permission to ${data.method} the requested resource ${data.url ? `'${data.url}'` : ''}`, statusCode);
  }
  /**
   * @constructor
   * @param {String} message The error message
   * @param {Number} statusCode The HTTP status code
   */
  constructor(message, statusCode = 500) {
    super();
    /**
     * Name of the error
     * @type {String}
     */
    this.name = 'AuthError';
    /**
     * The error message
     * @type {String}
     */
    this.message = message;
    /**
     * Relevant HTTP status code for the error
     * @type {Number}
     */
    this.statusCode = statusCode;
  }
}