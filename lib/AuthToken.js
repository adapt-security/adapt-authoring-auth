import { App } from 'adapt-authoring-core'
import { createObjectId } from 'adapt-authoring-mongodb'
import jwt from 'jsonwebtoken'
import { promisify } from 'node:util'
import { randomBytes } from 'node:crypto'
import { resolveTokenScopes } from './utils/resolveTokenScopes.js'

/** @ignore */ const jwtSignPromise = promisify(jwt.sign)
/** @ignore */ const jwtVerifyPromise = promisify(jwt.verify)

/** @ignore */ const collectionName = 'authtokens'
/** @ignore */ const schemaName = 'authtoken'
/** @ignore */ const tokenPrefix = 'adpt_pat_'
/**
 * Utilities for dealing with JSON web tokens
 * @memberof auth
 */
class AuthToken {
  /**
   * Retrieves the secret used during token generation
   * @type {String}
   */
  static get secret () {
    return App.instance.config.get('adapt-authoring-auth.tokenSecret')
  }

  static getSignature (token) {
    return token.split('.')[2]
  }

  /**
   * Strips the personal-access-token prefix (`adpt_pat_<frag>_`) from a token value,
   * returning the bare JWT. A value without the prefix (e.g. a session token) is returned unchanged.
   * @param {String} value The incoming token value
   * @return {String} The bare JWT
   */
  static stripTokenPrefix (value) {
    if (!value.startsWith(tokenPrefix)) {
      return value
    }
    const rest = value.slice(tokenPrefix.length)
    const sep = rest.indexOf('_')
    return sep === -1 ? rest : rest.slice(sep + 1)
  }

  /**
   * Decodes and stores any token data on the Express ClientRequest object
   * @param {external:ExpressRequest} req
   * @return {Promise}
   */
  static async initRequestData (req) {
    if (!req.auth.header) {
      throw App.instance.errors.MISSING_AUTH_HEADER
    }
    if (req.auth.header.type !== 'Bearer') {
      throw App.instance.errors.AUTH_HEADER_UNSUPPORTED
        .setData({ type: req.auth.header.type })
    }
    const token = await this.decode(req.auth.header.value)
    const [auth, mongodb, roles, users] = await App.instance.waitForModule('auth', 'mongodb', 'roles', 'users')
    const user = await users.findOne({ email: token.sub }, { strict: false })
    if (!user) {
      throw App.instance.errors.UNAUTHENTICATED
    }
    const authPlugin = auth.authentication.plugins[user.authType]

    if (!user.isEnabled) {
      throw App.instance.errors.ACCOUNT_DISABLED
    }
    if (!authPlugin) {
      throw App.instance.errors.UNKNOWN_AUTH_TYPE
        .setData({ authType: user.authType })
    }
    const userSchemaName = authPlugin.userSchema
    const tokenRecord = await mongodb.update(collectionName, { signature: token.signature }, { $set: { usedAt: new Date() } })

    const roleScopes = [].concat(...(await Promise.all(user.roles.map(r => roles.getScopesForRole(r)))))
    const scopes = Array.isArray(tokenRecord?.scopes) ? tokenRecord.scopes : roleScopes
    const isSuper = this.isSuper(scopes)

    Object.assign(req.auth, { isSuper, scopes, token, user, userSchemaName })
  }

  /**
   * Utility function to check if a user has super privileges
   * @param {Array} scopes The user's permission scopes
   * @return {Promise}
   */
  static isSuper (scopes) {
    return scopes.length === 1 && scopes[0] === '*:*'
  }

  /**
   * Generates a new token
   * @param {String} authType Authentication type used
   * @param {Object} userData The user to be encoded
   * @param {Object} options
   * @param {string} [options.lifespan] Lifespan of the token; pass `'never'` for a non-expiring token
   * @param {string} [options.name] Human-readable label for a personal access token
   * @param {Array<string>} [options.scopes] Restrict the token to a subset of the user's scopes; omit to inherit the user's full scopes. May not include the super wildcard.
   * @return {Promise} Resolves with the token value (personal access tokens are prefixed `adpt_pat_` and returned only once)
   */
  static async generate (authType, userData, options = {}) {
    const [auth, jsonschema, mongodb] = await App.instance.waitForModule('auth', 'jsonschema', 'mongodb')
    const _id = createObjectId().toString()
    const noExpiry = options.lifespan === 'never'
    const expiresIn = noExpiry ? undefined : (options.lifespan ?? App.instance.config.get('adapt-authoring-auth.defaultTokenLifespan'))

    // login tokens skip the roles lookup and inherit the full scope set at verification time
    let scopes
    if (authType === 'manual' || options.scopes !== undefined) {
      const roles = await App.instance.waitForModule('roles')
      const userScopes = [].concat(...(await Promise.all((userData.roles ?? []).map(r => roles.getScopesForRole(r)))))
      scopes = resolveTokenScopes({ authType, userScopes, requestedScopes: options.scopes }, App.instance.errors)
    }

    const token = await jwtSignPromise({ sub: userData.email, type: authType }, this.secret, {
      ...(expiresIn !== undefined ? { expiresIn } : {}),
      issuer: App.instance.config.get('adapt-authoring-auth.tokenIssuer')
    })
    // personal access tokens carry a random-fragment prefix so the stored hint distinguishes
    // them (a bare JWT always starts `eyJ`); the full value is returned only once
    const isManual = authType === 'manual'
    const fragment = isManual ? randomBytes(4).toString('hex') : undefined
    const value = isManual ? `${tokenPrefix}${fragment}_${token}` : token
    const exp = jwt.decode(token)?.exp
    const schema = await jsonschema.getSchema(schemaName)
    const data = schema.validate({
      _id,
      authType,
      signature: this.getSignature(token),
      createdAt: new Date().toISOString(),
      userId: userData._id.toString(),
      ...(scopes !== undefined ? { scopes } : {}),
      ...(options.name ? { name: options.name } : {}),
      ...(isManual ? { hint: `${tokenPrefix}${fragment}…` } : {}),
      ...(exp ? { expiresAt: new Date(exp * 1000).toISOString() } : {})
    })
    await mongodb.insert(collectionName, data)
    auth.log('debug', 'AUTH_TOKEN_ISSUED', data.userId.toString(), data.authType, expiresIn ?? 'never')
    return value
  }

  /**
   * Decodes a token
   * @param {String} token The token to decode
   * @return {Promise} Decoded token data
   */
  static async decode (token) {
    const jwtValue = this.stripTokenPrefix(token)
    let tokenData
    try {
      tokenData = await jwtVerifyPromise(jwtValue, this.secret)
      tokenData.signature = this.getSignature(jwtValue)
    } catch (e) {
      switch (e.name) {
        case 'JsonWebTokenError':
          throw App.instance.errors.AUTH_TOKEN_INVALID.setData({ error: e.message })
        case 'NotBeforeError':
          throw App.instance.errors.AUTH_TOKEN_NOT_BEFORE.setData({ error: e.message })
        case 'TokenExpiredError':
          try { await this.revoke({ signature: this.getSignature(jwtValue) }) } catch {}
          throw App.instance.errors.AUTH_TOKEN_EXPIRED
        default:
          throw App.instance.errors.AUTH_TOKEN_INVALID.setData({ error: e.message })
      }
    }
    if (!tokenData.sub) {
      throw App.instance.errors.INVALID_PARAMS.setData({ params: ['sub'] })
    }
    // verify we have a matching token in the DB
    const [record] = await this.find({ signature: this.getSignature(jwtValue) })
    if (!record) {
      throw App.instance.errors.UNAUTHENTICATED
    }
    return tokenData
  }

  /**
   * Retrieves an existing token
   * @param {Object} query
   * @param {Object} options
   * @param {Object} options.sanitise Whether the token data should be sanitised for returning via an API
   * @return {Promise<Array>} Resolves with the matching tokens (an empty array when none match)
   */
  static async find (query, options = {}) {
    const [jsonschema, mongodb] = await App.instance.waitForModule('jsonschema', 'mongodb')
    const results = await mongodb.find(collectionName, query)

    if (!options.sanitise) {
      return results
    }
    // strict:false strips internal fields (e.g. signature) from the output; the
    // default strict throws MODIFY_PROTECTED_ATTR when a protected field is present.
    // _id isn't a declared schema property, so carry it through for the API consumer.
    const schema = await jsonschema.getSchema(schemaName)
    return results.map(r => ({ _id: r._id, ...schema.sanitise(r, { isInternal: true, strict: false }) }))
  }

  /**
   * Invalidates an existing token
   * @param {Object} query Database query to identify tokens to be deleted
   * @return {Promise} Resolves with the value from MongoDBModule#delete
   */
  static async revoke (query) {
    const [auth, mongodb] = await App.instance.waitForModule('auth', 'mongodb')
    const results = await this.find(query)
    results.forEach(r => auth.log('debug', 'AUTH_TOKEN_REVOKED', r.userId.toString(), r.authType))
    return mongodb.getCollection(collectionName).deleteMany(query)
  }
}

export default AuthToken
