'use strict'

const path = require('path')
const fs = require('fs').promises
const assert = require('assert')
const _ = require('lodash')
const async = require('async')
const crypto = require('crypto')
const DbBase = require('@bitfinex/bfx-facs-db-sqlite')
const uuidv4 = require('uuid/v4')
const { cloneDeep } = require('@bitfinex/lib-js-util-base')
const { google } = require('googleapis')
const migrations = require('./migrations')
const AdminUserRepository = require('./src/admin-user-repo')
const PrivilegeRepository = require('./src/privilege-repo')
const AdminPrivilegeRepository = require('./src/admin-privilege-repo')

async function verify (password, hash) {
  return new Promise((resolve, reject) => {
    const [salt, key] = hash.split(':')
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) reject(err)
      resolve(key === derivedKey.toString('hex'))
    })
  })
}

/**
 * @typedef {{ username: string, password: string }} LoginUserT
 * @typedef {{
 *  access_token: string | null;
 *  token_type: string | null;
 *  expiry_date: string | null;
 * }} Credentials
 * @typedef {{
 *  access_token: string | null;
 *  token_type: string | null;
 *  expiry_date: number | null;
 *  refresh_token?: string | null;
 *  id_token?: string | null;
 *  scope?: string;
 * }} TokenCredentials
 * @typedef { AdminUserRepository.AddedAdminT & {
 *  username: string,
 *  token: string,
 *  expires_at: Date
 * }} LoginResp
 */
class GoogleAuth extends DbBase {
  constructor (caller, opts = {}, ctx) {
    opts.name = 'auth-google'
    opts.runSqlAtStart = [
      ...AdminUserRepository.runSqlAtStart
    ]
    super(caller, opts, ctx)

    this.name = 'auth-google'
    this._hasConf = true
    this.useRedis = opts.useRedis || false
    this.mongoFac = opts.mongoFac || caller.dbMongo_m0
    this.redisFac = opts.redisFac || caller.redis_gc0

    this.init()

    if (opts.conf) this.conf = opts.conf
    this.checkAdmAccessLevel = this.checkAdmAccessLevel.bind(this)
  }

  /**
   * Get all configured Google client entries (web client + mobile clients)
   * @returns {{ entries: Object }}
   */
  _googleClientEntries () {
    const { google = {} } = this.conf
    const entries = {}

    // Web client config (backward compatibility - single client setup)
    if (google.clientId) {
      entries.webClient = {
        clientId: google.clientId,
        clientSecret: google.clientSecret,
        redirectUris: google.redirectUris
      }
    }

    // Mobile clients config
    if (google.mobile && typeof google.mobile === 'object') {
      Object.entries(google.mobile).forEach(([key, value]) => {
        if (value && value.clientId) {
          entries[key] = value
        }
      })
    }

    return {
      entries
    }
  }

  /**
   * Get all configured client IDs for token audience validation
   * @returns { string[] }
   */
  _googleClientIds () {
    const { entries } = this._googleClientEntries()
    return Object.values(entries)
      .map(c => c.clientId)
      .filter(Boolean)
  }

  /**
   * Resolve which Google client config to use based on clientKey hint and/or token audience
   * Security: Token audience (aud) is the source of truth - clientKey is just a hint
   * @param {Object} opts
   * @param {string|undefined} opts.clientKey - Optional hint from frontend (not trusted alone)
   * @param {string|undefined} opts.tokenAud - Token audience from verified Google ID token (trusted)
   * @returns {Object} Client config with clientId, clientSecret, redirectUris
   * @throws {Error} AUTH_FAC_INVALID_GOOGLE_CLIENT if client not found or mismatch
   */
  _resolveGoogleClient ({ clientKey, tokenAud } = {}) {
    const { entries } = this._googleClientEntries()

    // Step 1: If we have token audience, use it as source of truth (most secure)
    if (tokenAud) {
      const matchedByAud = Object.keys(entries).find(key => entries[key]?.clientId === tokenAud)

      if (!matchedByAud) {
        throw new Error('AUTH_FAC_INVALID_GOOGLE_CLIENT')
      }

      // If clientKey was provided, verify it matches the token's audience
      if (clientKey && clientKey !== matchedByAud) {
        throw new Error('AUTH_FAC_INVALID_GOOGLE_CLIENT')
      }

      return entries[matchedByAud]
    }

    // Step 2: If no token audience, use clientKey hint (for OAuth code exchange flows)
    if (clientKey) {
      if (!entries[clientKey]) {
        throw new Error('AUTH_FAC_INVALID_GOOGLE_CLIENT')
      }
      return entries[clientKey]
    }

    // Step 3: Fallback to main client (backward compatibility)
    if (entries.webClient) {
      return entries.webClient
    }

    throw new Error('AUTH_FAC_INVALID_GOOGLE_CLIENT')
  }

  _start (cb) {
    if (!this.conf.useDB) {
      return cb()
    }

    async.series([
      async () => {
        if (this.conf.useDB) {
          const db = this.opts.db
          const dbDir = path.dirname(db)
          try {
            await fs.access(dbDir)
          } catch (err) {
            if (err && err.code === 'ENOENT') {
              await fs.mkdir(dbDir)
            }
          }
        }
      },
      super._start.bind(this),
      async () => {
        this.adminUserRepo = new AdminUserRepository(this.db, this.conf)
        this.privilegeRepo = new PrivilegeRepository(this.db, this.conf)
        this.adminPrivilegeRepo = new AdminPrivilegeRepository(this.db, this.conf)
      },
      cb => {
        this.runMigrations(migrations, cb)
      },
      async () => {
        await this._saveAdminsFromConfig()
      }
    ], cb)
  }

  _stop (cb) {
    if (!this.conf.useDB) {
      return cb()
    }

    super._stop(cb)
  }

  /**
   * @param {{ user: LoginUserT, google: Credentials, ip: number }} args
   * @param { (err: null|Error, res: LoginResp) => void } cb
   * @returns { Promise<void> }
   */
  async loginAdmin (args, cb) {
    const { user, google, ip } = args

    if (!user && !google) {
      return cb(new Error('AUTH_FAC_LOGIN_KEYS_MISSING'))
    }

    const complete = (user)
      ? ['username', 'password'].every(k => k in user)
      : ['access_token', 'token_type', 'expiry_date'].every(k => k in google) ||
        ['credential'].every(k => k in google)
    if (!complete) return cb(new Error('AUTH_FAC_LOGIN_KEYS_MISSING'))

    return (user)
      ? this._loginAdminPass(user, ip, cb)
      : this._loginAdminGoogle(google, ip, cb)
  }

  async _loginAdminPass (params, ip, cb) {
    const {
      valid, level, extra
    } = await this.basicAuthAdmLogCheck(params.username, params.password)

    return (valid)
      ? this._createAdminToken(params.username, ip, level, extra, cb)
      : cb(new Error('AUTH_FAC_LOGIN_INCORRECT_USERNAME_PASSWORD'))
  }

  /**
   * this is used to validate code generated from google sso to fetch access token, id token
   * we use id token to get email and validate
   * @param {string} code
   * @param {string} redirectUriKey - the redirect uri key to use for the google client
   * @param {string|undefined} clientKey - optional client key to use for the google client
   * @returns {Promise<TokenCredentials>}
   */
  async getTokensFromCode (code, redirectUriKey, clientKey) {
    const oAuth2Client = this._getOAuth2Client({ clientKey, redirectUriKey })
    const { tokens } = await oAuth2Client.getToken(code)
    return tokens
  }

  async _loginAdminGoogle (params, ip, cb) {
    const { clientKey } = params || {}
    try {
      const email = await this.googleEmailFromToken(params, clientKey)
      const { valid, level, extra } = await this._validAdminUserGoogleEmail(email)
      return (valid)
        ? this._createAdminToken(email, ip, level, extra, cb)
        : cb(new Error('AUTH_FAC_ACCOUNT_IS_NOT_VALID'))
    } catch (e) {
      console.log(e)
      cb(new Error('AUTH_FAC_ACCOUNT_IS_NOT_VALID'))
    }
  }

  async _createAdminToken (user, ip, level, extra = {}, cb) {
    const username = user
    const token = 'ADM-' + uuidv4()
    const exp = new Date()
    exp.setHours(exp.getHours() + 8)
    const query = { username, token, ip, level, expires_at: exp }
    try {
      await this._createUniqueAndExpireDbToken(query)
      const privileges = await this.adminPrivilegeRepo.getAdminPrivileges(extra.id)
      return cb(null, { username, token, level, privileges, ...extra, expires_at: exp })
    } catch (e) {
      return cb(new Error('AUTH_FAC_ADMIN_TOKEN_CREATE_ERROR'))
    }
  }

  _tokenKey (query) {
    return `adminTokens:${query.token}:${query.ip}`
  }

  _createUniqueAndExpireDbToken (query) {
    if (!this.useRedis) { // mongodb
      const mc = this.mongoFac.db
      const collection = 'adminTokens'
      return new Promise((resolve, reject) => {
        mc.collection(collection)
          .insertOne(query, (err, res) => {
            if (err) return reject(err)
            resolve()
          })
      })
    } else { // redis
      const key = this._tokenKey(query)
      const expires_at = (query.expires_at - new Date()) / 1000 // eslint-disable-line camelcase
      return new Promise((resolve, reject) => {
        this.redisFac.cli_rw.multi([
          ['set', key, JSON.stringify(query)],
          ['expire', key, expires_at] // eslint-disable-line camelcase
        ]).exec((err, result) => {
          if (err) return reject(err)
          resolve()
        })
      })
    }
  }

  async _validAdminUserGoogleEmail (mail) {
    return this._whiteListEmail(mail)
  }

  preAdminTokenCheck (authToken) {
    return (authToken && authToken.length === 2 && authToken[0])
      ? authToken[0].startsWith('ADM')
      : false
  }

  async checkAdminRedis (authToken, level = 0) {
    const preCheck = this.preAdminTokenCheck(authToken)
    if (!preCheck) return false
    const token = authToken[0]
    const ip = authToken[1].ip
    const key = this._tokenKey({ token, ip })
    const json = await this.redisFac.cli_rw.get(key)
    const data = JSON.parse(json)
    return data && this.checkAdmAccessLevel(data.username, level)
  }

  /**
   * Create OAuth2 client for Google authentication
   * Note: redirectUris are optional for mobile clients (they use ID tokens, not OAuth code flow)
   * @param {Object} opts
   * @param {string|undefined} opts.clientKey - Client key hint
   * @param {string|undefined} opts.redirectUriKey - Redirect URI key (e.g., 'ssoAuth') - only needed for web OAuth flows
   * @param {string|undefined} opts.tokenAud - Token audience for validation
   * @returns {google.auth.OAuth2}
   */
  _getOAuth2Client ({ clientKey, redirectUriKey, tokenAud } = {}) {
    const { clientId, clientSecret, redirectUris } = this._resolveGoogleClient({
      clientKey,
      tokenAud
    })

    // redirectUri is only needed for OAuth code exchange flows (web apps)
    // Mobile apps don't need it since they use ID tokens directly
    const redirectUri = redirectUriKey ? redirectUris?.[redirectUriKey] : undefined

    return new google.auth.OAuth2(
      clientId,
      clientSecret,
      redirectUri
    )
  }

  /**
   * Get user info from Google token (ID token or OAuth access token)
   * For mobile apps: Uses ID token (credential) - validates audience automatically
   * For web apps: Uses OAuth access token - requires clientKey for client selection
   * @param {{ credential: string, access_token: string, token_type: string, expires_in: number, id_token: string, scope: string }} payload
   * @param {string|undefined} clientKey - Optional hint for client selection (validated against token audience)
   * @returns { Promise<Object> }
   */
  async googleUserInfoFromToken (payload, clientKey = undefined) {
    // Mobile apps: ID token flow (credential field)
    if (payload?.credential) {
      const allowedAudiences = this._googleClientIds()
      const verifier = new google.auth.OAuth2()

      // Verify ID token signature and validate audience
      const ticket = await verifier.verifyIdToken({
        idToken: payload.credential,
        ...(allowedAudiences.length > 0 && { audience: allowedAudiences })
      })

      const tokenPayload = ticket.getPayload()

      if (!tokenPayload?.aud) {
        throw new Error('AUTH_FAC_INVALID_GOOGLE_TOKEN')
      }

      // Validate that token audience matches a configured client
      // Also verify clientKey hint matches if provided
      this._resolveGoogleClient({
        clientKey,
        tokenAud: tokenPayload.aud
      })

      return tokenPayload
    }

    // Web apps: OAuth access token flow
    const oAuth2Client = this._getOAuth2Client({ clientKey })
    oAuth2Client.setCredentials(payload)
    const oauth2 = google.oauth2({ version: 'v2', auth: oAuth2Client })

    try {
      const userInfo = await oauth2.userinfo.get()
      return userInfo?.data
    } catch (error) {
      throw new Error('AUTH_FAC_ERROR_ASK_EMAIL:' + error.toString())
    }
  }

  /**
   * returns the email from the google token based on the payload and scope at least email
   * @param {{ credential: string, access_token: string, token_type: string, expires_in: number, id_token: string, scope: string }} payload
   * @param {string|undefined} clientKey - optional client key to use for the google client
   * @returns { Promise<string> }
   */
  async googleEmailFromToken (payload, clientKey = undefined) {
    const userInfo = await this.googleUserInfoFromToken(payload, clientKey)
    return userInfo?.email
  }

  async _whiteListEmail (sentEmail) {
    const admin = await this._getAdmin(sentEmail)

    if (!admin) return { valid: false }

    const { email, password, level, ...extra } = admin

    return {
      valid: true,
      level,
      extra
    }
  }

  async _saveAdminsFromConfig () {
    const admins = this.conf.ADM_USERS
    if (!(admins && Array.isArray(admins))) return true
    const adminDbHasData = await this.adminUserRepo.doesAdminDbHaveData()
    if (adminDbHasData) return true

    const tasks = admins.map(async (admin) => {
      const { email } = admin
      const adm = await this._getAdmin(email, false)
      if (adm) return adm

      return this.addAdmin(cloneDeep(admin))
    })

    await Promise.all(tasks)
  }

  /**
   * @param { AdminUserRepository.AddAdminT } user
   * @returns { Promise<AdminUserRepository.AddedAdminT> }
   */
  async addAdmin (user) {
    assert.ok(this.conf.useDB, 'Cannot add admins if DB is not available')

    return this.adminUserRepo.add(user)
  }

  async updateAdmin (email, user) {
    assert.ok(this.conf.useDB, 'Cannot update admins if DB is not available')

    return this.adminUserRepo.update(email, user)
  }

  async updateAdminPassword (email, newPassword, oldPassword) {
    assert.ok(this.conf.useDB, 'Cannot update admins if DB is not available')

    return this.adminUserRepo.updatePassword(email, newPassword, oldPassword)
  }

  async resetAdminPassword (email, newPassword, passwordResetToken) {
    assert.ok(this.conf.useDB, 'Cannot update admins if DB is not available')

    return this.adminUserRepo.resetPassword(email, newPassword, passwordResetToken)
  }

  async removeAdmin (idOrEmail) {
    assert.ok(this.conf.useDB, 'Cannot remove admins if DB is not available')

    return this.adminUserRepo.remove(idOrEmail)
  }

  async basicAuthAdmLogCheck (sentEmail, sentPassword) {
    const admin = await this._getAdmin(sentEmail)

    const isValidPassword = this.conf.useDB
      ? sentPassword && admin?.password && (await verify(sentPassword, admin.password))
      : admin?.password === sentPassword

    if (!(
      admin &&
      admin.password && // password cant be empty or false
      isValidPassword
    )) {
      return { valid: false }
    }

    const { email, password, level, ...extra } = admin

    return {
      valid: true,
      level,
      extra
    }
  }

  async checkAdmAccessLevel (adminEmail, level) {
    const admin = await this._getAdmin(adminEmail)
    const valid = !!admin && admin.level <= level
    return valid
  }

  async checkAdmIsReadOnly (adminEmail) {
    const admin = await this._getAdmin(adminEmail)
    if (!admin) throw new Error('Searched admin was not found')

    return !!admin.readOnly
  }

  async checkAdmHasBlockPrivilege (adminEmail) {
    const admin = await this._getAdmin(adminEmail)
    if (!admin) throw new Error('Searched admin was not found')

    return !!(admin.level === 0 || admin.blockPrivilege)
  }

  async checkAdmHasAnalyticsPrivilege (adminEmail) {
    const admin = await this._getAdmin(adminEmail)
    if (!admin) throw new Error('Searched admin was not found')

    return !!(admin.level === 0 || admin.analyticsPrivilege)
  }

  async checkAdmHasManageAdminsPrivilege (adminEmail) {
    const admin = await this._getAdmin(adminEmail)
    if (!admin) throw new Error('Searched admin was not found')

    return !!(admin.level === 0 && admin.manageAdminsPrivilege)
  }

  async checkAdmHasCasesPrivilege (adminEmail) {
    const admin = await this._getAdmin(adminEmail)
    if (!admin) throw new Error('Searched admin was not found')

    return !!(admin.level === 0 && admin.casesPrivilege)
  }

  async checkAdmHasFetchMotivationsPrivilege (adminEmail) {
    const admin = await this._getAdmin(adminEmail)
    if (!admin) throw new Error('Searched admin was not found')

    return !!(admin.level === 0 || admin.fetchMotivationsPrivilege)
  }

  /**
   * @param { string|number } emailOrId - Identifier used for searching the admin, it can be either the admin email address or its database id.
   * @param { boolean } [active=true] - Flag for considering only the active users, it is `true` by default. If `false`, it will search through inactive users too.
   * @param { boolean } [id=false] - Flag for searching as well by id criterion, it's `false` by default. If `true`, enables the mentioned behavior.
   * @returns { Promise<AdminUserRepository.BaseAdminT & { timestamp: Date, active: boolean }> }
   */
  async getAdmin (emailOrId, active = true, id = false) {
    const admin = await this._getAdmin(emailOrId, active, id)
    const displayKeys = ['id', 'email', 'level', 'blockPrivilege', 'company',
      'analyticsPrivilege', 'manageAdminsPrivilege', 'casesPrivilege', 'fetchMotivationsPrivilege', 'readOnly', 'active', 'timestamp', AdminUserRepository.FORMS_FIELD, 'whitelistedIps']

    if (this.conf.useDB && admin) {
      for (const field of AdminUserRepository.JSON_FIELDS) {
        if (admin[field]) admin[field] = JSON.parse(admin[field])
      }
    }

    return admin
      ? _.pick(admin, displayKeys)
      : admin
  }

  async _getAdmin (emailOrId, active = true, id = false) {
    if (!emailOrId) return false

    return this.conf.useDB
      ? this.adminUserRepo.getAdmin(emailOrId, active, id)
      : this._getAdminFromConfig(emailOrId)
  }

  _getAdminFromConfig (email) {
    const admins = this.conf.ADM_USERS || []

    for (const adm of admins) {
      if (adm.email.toLowerCase() === email.toLowerCase()) return adm
    }

    return false
  }

  async getAdminEmails (active = true, company) {
    return this.conf.useDB
      ? this.adminUserRepo.getAdminEmails(active, company)
      : this._getAdminEmailsFromConfig(company)
  }

  async _getAdminEmailsFromConfig (company) {
    const admins = this.conf.ADM_USERS || []
    return admins
      .filter(u => company
        ? u.company.toLowerCase() === company.toLowerCase()
        : true
      )
      .map(
        u => u.email.toLowerCase()
      )
  }

  async hasPassword (email) {
    const admin = await this._getAdmin(email)
    return !!admin?.password
  }

  addPrivilege (name) {
    return this.privilegeRepo.add({ name })
  }

  getAllPrivileges () {
    return this.privilegeRepo.findAll()
  }

  /**
   *
   * @param {string} emailOrId
   * @param {number} privilegeId
   * @returns {Promise<{ admin: emailOrId, privilege: string }>}
   */
  async assignAdminPrivilege (emailOrId, privilegeId) {
    const admin = await this.adminUserRepo.getAdmin(emailOrId, true, true)
    if (!admin) throw new Error('INVALID_ADMIN')

    const privilege = await this.privilegeRepo.findById(privilegeId)
    if (!privilege) throw new Error('INVALID_PRIVILEGE_ID')

    await this.adminPrivilegeRepo.add({ adminId: admin.id, privilegeId: privilege.id })
    return { admin: emailOrId, privilege: privilege.name }
  }

  /**
   *
   * @param {string} emailOrId
   * @param {number} privilegeId
   * @returns {Promise<{ admin: emailOrId, privilege: string }>}
   */
  async unAssignAdminPrivilege (emailOrId, privilegeId) {
    const admin = await this.adminUserRepo.getAdmin(emailOrId, true, true)
    if (!admin) throw new Error('INVALID_ADMIN')

    const privilege = await this.privilegeRepo.findById(privilegeId)
    if (!privilege) throw new Error('INVALID_PRIVILEGE_ID')

    await this.adminPrivilegeRepo.remove(admin.id, privilege.id)
    return { admin: emailOrId, privilege: privilege.name }
  }

  /**
   *
   * @param {string} emailOrId
   * @param {string} privilege
   * @returns {Promise<Boolean>}
   */
  async checkAdminHasRequiredPrivilege (emailOrId, privilege) {
    const admin = await this.adminUserRepo.getAdmin(emailOrId, true, true)
    if (!admin) throw new Error('INVALID_ADMIN')

    const adminPrivilege = await this.adminPrivilegeRepo.findAdminPrivilege(admin.id, privilege)
    return Boolean(adminPrivilege)
  }

  /**
   * @param { string } email
   * @param { boolean } [active=true]
   * @param { boolean } [id=false]
   * @returns {Promise<AdminUserRepository.BaseAdminT & {timestamp: Date, active: boolean, privileges: Array<{id: number, name: string}>}>}
   */
  async getAdminWithPrivileges (email, active = true, id = false) {
    const admin = await this.getAdmin(email, active, id)
    if (!admin) return admin

    const privileges = await this.adminPrivilegeRepo.getAdminPrivileges(admin.id)

    return { ...admin, privileges }
  }
}

module.exports = GoogleAuth
