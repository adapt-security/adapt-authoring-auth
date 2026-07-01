/**
 * Decides the scopes to persist on a new auth token, enforcing the token-scope rules:
 * a super user may not mint a `manual` (full-scope, copy-pasteable) bearer token; explicit
 * scopes may never include the super wildcard, and — for non-super users — may not exceed
 * the user's own scopes (a super holds all scopes, so may request any concrete set).
 * @param {object} params
 * @param {string} params.authType Authentication type of the token being generated
 * @param {Array<string>} params.userScopes The user's role-derived scopes
 * @param {Array<string>} [params.requestedScopes] Explicit scopes for a scoped token; omit to inherit the user's full scopes
 * @param {object} errors Error registry (App.instance.errors) used to throw
 * @returns {Array<string>|undefined} Scopes to persist on the token, or undefined to inherit the user's full scopes
 * @memberof auth
 */
export function resolveTokenScopes ({ authType, userScopes, requestedScopes }, errors) {
  const isSuper = userScopes.length === 1 && userScopes[0] === '*:*'
  if (isSuper && authType === 'manual') {
    throw errors.SUPER_TOKEN_FORBIDDEN
  }
  if (requestedScopes === undefined) {
    return undefined
  }
  if (!Array.isArray(requestedScopes)) {
    throw errors.INVALID_PARAMS.setData({ params: ['scopes'] })
  }
  if (requestedScopes.includes('*:*')) {
    throw errors.SUPER_TOKEN_FORBIDDEN
  }
  if (!isSuper) {
    const invalid = requestedScopes.filter(s => !userScopes.includes(s))
    if (invalid.length) {
      throw errors.TOKEN_SCOPE_INVALID.setData({ scopes: invalid })
    }
  }
  return requestedScopes
}
