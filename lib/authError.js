/**
* Error for authentication & authorisation
*/
class AuthError extends Error {
  /**
  * Creates a new authentication error
  * @param {String} msg The error message
  * @return {AuthError}
  */
  static Authenticate(msg) {
    return new AuthError(`You couldn't be authenticated with the API, ${msg}`, 401);
  }
  /**
  * Creates a new authorisation error
  * @param {Object} data Data to be formatted into an error
  * @return {AuthError}
  */
  static Authorise(data) {
    return new AuthError(`You don't have permission to ${data.method} the requested resource ${data.url ? `'${data.url}'` : ''}`, 403);
  }
  /**
  * @constructor
  * @param {Object} data Data to be formatted into an error
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

module.exports = AuthError;
