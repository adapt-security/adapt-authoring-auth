/**
*
*/
class AuthError extends Error {
  static Authenticate(msg) {
    return new AuthError({
      name: 'AuthenticationError',
      message: `You don't have permission to access the API, ${msg}`,
      statusCode: 401
    });
  }
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
