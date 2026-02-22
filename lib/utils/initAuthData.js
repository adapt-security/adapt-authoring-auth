/**
 * Adds auth data to the incoming request
 * @param {external:ExpressRequest} req
 * @return {Promise}
 * @memberof auth
 */
export async function initAuthData (req) {
  req.auth = {}
  const authHeader = req.get('Authorization') || req.headers.Authorization
  if (!authHeader) {
    return
  }
  const [type, value] = authHeader.split(' ')
  req.auth.header = { type, value }
}
