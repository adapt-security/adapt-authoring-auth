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
    return new AuthError({
      name: 'AuthenticationError',
      message: `You don't have permission to access the API, ${msg}`,
      statusCode: 401
    });
  }
  /**
  * Creates a new authorisation error
  * @param {Object} data
  * @return {AuthError}
  */
  static Authorise(data) {
    return new AuthError({
      name: 'AuthorisationError',
      message: `You don't have permission to ${data.method} the requested resource '${data.url}'`,
      statusCode: 403
    });
  }
  constructor(data) {
    super();
    Object.assign(this, data);
  }
}

module.exports = AuthError;
