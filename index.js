'use strict'

const path = require('path')
const fs = require('fs').promises
const assert = require('assert')
const _ = require('lodash')
const async = require('async')
const crypto = require('crypto')
const DbBase = require('bfx-facs-db-sqlite')
const uuidv4 = require('uuid/v4')
const { google } = require('googleapis')
const { UserError } = require('./errors')
const migrations = require('./migrations')
const { cloneDeep, isNil, pick } = require('@bitfinexcom/lib-js-util-base')
const { VALID_DAILY_LIMIT_CATEGORIES, MIN_ADMIN_LEVEL, DB_TABLES, MAX_ADMIN_LEVEL } = require('./shared')

const SHOULD_STRINGIFY = ['forms', 'dailyLimitConfig']

async function hash (password, salt = '') {
  return new Promise((resolve, reject) => {
    const computedSalt = salt || crypto.randomBytes(8).toString('hex')

    crypto.scrypt(password, computedSalt, 64, (err, derivedKey) => {
      if (err) reject(err)
      resolve(computedSalt + ':' + derivedKey.toString('hex'))
    })
  })
}

async function verify (password, hash) {
  return new Promise((resolve, reject) => {
    const [salt, key] = hash.split(':')
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) reject(err)
      resolve(key === derivedKey.toString('hex'))
    })
  })
}

const tableName = DB_TABLES.ADMIN_USERS
/**
 * @typedef {('opened'|'displayed')} DailyLimitCategory
 * @typedef {{
 *  alert: number
 *  block: number
 * }} DailyLimitConfig
 * @typedef {Record<DailyLimitCategory, DailyLimitConfig>} DailyLimitConfigsByCategory
 * @typedef {{
 *  email: string,
 *  level: number,
 *  readOnly?: boolean,
 *  blockPrivilege?: boolean,
 *  analyticsPrivilege?: boolean,
 *  manageAdminsPrivilege?: boolean,
 *  fetchMotivationsPrivilege?: boolean,
 *  passwordResetToken?: string,
 *  passwordResetSentAt?: Date,
 *  company?: string,
 *  forms?: string[],
 *  dailyLimitConfig?: DailyLimitConfigsByCategory
 * }} BaseAdminT
 * @typedef { BaseAdminT & { password: string }} AddAdminT
 * @typedef { BaseAdminT & {
 *  active: boolean,
 *  id: number
 * }} AddedAdminT
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
 * @typedef { AddedAdminT & {
 *  username: string,
 *  token: string,
 *  expires_at: Date
 * }} LoginResp
 * @typedef {DailyLimitConfigsByCategory} AdminLevelDailyLimitConfigsByCategory
 * @typedef {(0|1|2|3|4)} AdminLevel
 * @typedef {Record<AdminLevel, DailyLimitConfig>} AdminLevelDailyLimitConfigsByAdminLevel
 */
class GoogleAuth extends DbBase {
  constructor (caller, opts = {}, ctx) {
    opts.name = 'auth-google'
    opts.runSqlAtStart = [
      `CREATE TABLE IF NOT EXISTS ${tableName} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT,
        level INTEGER NOT NULL,
        active TINYINTEGER DEFAULT 1,
        readOnly TINYINTEGER,
        blockPrivilege TINYINTEGER,
        analyticsPrivilege TINYINTEGER,
        manageAdminsPrivilege TINYINTEGER,
        passwordResetToken TEXT,
        passwordResetSentAt DATETIME,
        company TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        forms TEXT
        dailyLimitConfig TEXT
      )`,
      `CREATE UNIQUE INDEX IF NOT EXISTS uidx_email ON ${tableName}(email ASC)`
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
   * @returns { void }
   */
  loginAdmin (args, cb) {
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
   * @param {'sso_auth'} redirectUriKey
   * @returns {Promise<TokenCredentials>}
   */
  async getTokensFromCode (code, redirectUriKey) {
    const oAuth2Client = this._getOAuth2Client(redirectUriKey)
    const { tokens } = await oAuth2Client.getToken(code)
    return tokens
  }

  async _loginAdminGoogle (params, ip, cb) {
    try {
      const email = await this.googleEmailFromToken(params)
      const { valid, level, extra } = await this._validAdminUserGoogleEmail(email)
      return (valid)
        ? this._createAdminToken(email, ip, level, extra, cb)
        : cb(new Error('AUTH_FAC_ACCOUNT_IS_NOT_VALID'))
    } catch (e) {
      console.log(e)
      cb(new Error('AUTH_FAC_INCORRECT_GOOGLE_TOKEN'))
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
      return cb(null, { username, token, level, ...extra, expires_at: exp })
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

  _getOAuth2Client (redirectUriKey = undefined) {
    const { clientId, clientSecret, redirectUris } = this.conf.google
    return new google.auth.OAuth2(
      clientId,
      clientSecret,
      redirectUriKey ? redirectUris[redirectUriKey] : undefined
    )
  }

  /**
   * returns the user info from the google token based on the payload and scope expected profile and email
   * @param {{ credential: string, access_token: string, token_type: string, expires_in: number, id_token: string, scope: string }} payload
   * @returns { Promise<Object> }
   */
  async googleUserInfoFromToken (payload) {
    const oAuth2Client = this._getOAuth2Client()

    if (payload?.credential) {
      const ticket = await oAuth2Client.verifyIdToken({
        idToken: payload.credential
      })
      return ticket.getPayload()
    }
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
   * @returns { Promise<string> }
   */
  async googleEmailFromToken (payload) {
    const userInfo = await this.googleUserInfoFromToken(payload)
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
    const adminDbHasData = await this._checkIfAdminDbHasData()
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
   * @param { AddAdminT } user
   * @returns { Promise<AddedAdminT> }
   */
  async addAdmin (user) {
    assert.ok(this.conf.useDB, 'Cannot add admins if DB is not available')

    const {
      email,
      password,
      level,
      readOnly,
      blockPrivilege,
      analyticsPrivilege,
      manageAdminsPrivilege,
      fetchMotivationsPrivilege,
      company,
      dailyLimitConfig
    } = user

    assert.ok(typeof email === 'string', 'Email is required')
    assert.ok(typeof level === 'number', 'Level must be a number')

    if (password) {
      assert.ok(typeof password === 'string', 'Password should be a string')
    }

    if (readOnly) {
      assert.ok(typeof readOnly === 'boolean', 'readOnly should be a boolean')
    }

    if (blockPrivilege) {
      assert.ok(typeof blockPrivilege === 'boolean', 'blockPrivilege should be a boolean')
    }

    if (analyticsPrivilege) {
      assert.ok(typeof analyticsPrivilege === 'boolean', 'analyticsPrivilege should be a boolean')
    }

    if (manageAdminsPrivilege) {
      assert.ok(typeof manageAdminsPrivilege === 'boolean', 'manageAdminsPrivilege should be a boolean')
    }

    if (fetchMotivationsPrivilege) {
      assert.ok(typeof fetchMotivationsPrivilege === 'boolean', 'fetchMotivationsPrivilege should be a boolean')
    }

    if (company) {
      assert.ok(typeof company === 'string', 'company should be a string')
    }

    this._validateDailyLimitConfig(dailyLimitConfig)

    const adm = await this._getAdmin(email, false)
    if (adm) throw new UserError('ADMIN_ACCOUNT_EXISTS')

    const hashedPassword = password
      ? await hash(password, this.conf.hashSalt)
      : null

    user.password = hashedPassword

    return new Promise((resolve, reject) => {
      const keys = Object.keys(user)

      this.db.run(
        `INSERT INTO ${tableName} (${keys.join(', ')}) VALUES (${Array(keys.length).fill('?').join(', ')})`,
        this._convertUserObjectToValuesArray(user),
        function (err) {
          if (err) return reject(err)

          resolve({
            email,
            level,
            readOnly,
            blockPrivilege,
            analyticsPrivilege,
            manageAdminsPrivilege,
            fetchMotivationsPrivilege,
            company,
            active: true,
            id: this.lastID
          })
        }
      )
    })
  }

  async updateAdmin (email, user) {
    assert.ok(this.conf.useDB, 'Cannot add admins if DB is not available')

    const {
      password,
      level,
      readOnly,
      blockPrivilege,
      analyticsPrivilege,
      manageAdminsPrivilege,
      fetchMotivationsPrivilege,
      company,
      active,
      dailyLimitConfig
    } = user

    assert.ok(typeof email === 'string', 'Email is required')

    if (user.email) {
      throw new UserError('Email cannot be updated')
    }

    if (password) {
      throw new UserError('Use Change Password endpoint to update user password')
    }

    if (level) {
      assert.ok(typeof level === 'number', 'Level must be a number')
    }

    if (readOnly) {
      assert.ok(typeof readOnly === 'boolean', 'readOnly should be a boolean')
    }

    if (blockPrivilege) {
      assert.ok(typeof blockPrivilege === 'boolean', 'blockPrivilege should be a boolean')
    }

    if (analyticsPrivilege) {
      assert.ok(typeof analyticsPrivilege === 'boolean', 'analyticsPrivilege should be a boolean')
    }

    if (manageAdminsPrivilege) {
      assert.ok(typeof manageAdminsPrivilege === 'boolean', 'manageAdminsPrivilege should be a boolean')
    }

    if (fetchMotivationsPrivilege) {
      assert.ok(typeof fetchMotivationsPrivilege === 'boolean', 'fetchMotivationsPrivilege should be a boolean')
    }

    if (company) {
      assert.ok(typeof company === 'string', 'company should be a string')
    }

    if (active) {
      assert.ok(typeof active === 'boolean', 'active should be a boolean')
    }

    this._validateDailyLimitConfig(dailyLimitConfig)

    const adm = await this._getAdminOrThrowError(email, !active)

    return new Promise((resolve, reject) => {
      const keys = Object.keys(user)

      this.db.run(
        `UPDATE ${tableName} SET ${keys.join(' = ?, ')} = ? WHERE id = ?`,
        this._convertUserObjectToValuesArray(user).concat(adm.id),
        function (err) {
          if (err) return reject(err)

          resolve(user)
        }
      )
    })
  }

  _validateDailyLimitConfig (dailyLimitConfig) {
    if (dailyLimitConfig) {
      assert.ok(
        (
          typeof dailyLimitConfig === 'object' &&
          Object.keys(dailyLimitConfig).every(k => VALID_DAILY_LIMIT_CATEGORIES.some(c => c === k)) &&
          Object.values(dailyLimitConfig).every(v => (_.isInteger(v.alert) && v.alert >= 0 && _.isInteger(v.block) && v.block >= 0))
        ),
        'dailyLimitConfig must be a DailyLimitConfigsByCategory object'
      )
    }
  }

  _convertUserObjectToValuesArray (user) {
    const keys = Object.keys(user)
    return keys.map(key => SHOULD_STRINGIFY.some(ss => key === ss) ? JSON.stringify(user[key]) : user[key])
  }

  async updateAdminPassword (email, newPassword, oldPassword) {
    assert.ok(this.conf.useDB, 'Cannot add admins if DB is not available')

    assert.ok(typeof email === 'string', 'Email is required')
    assert.ok(typeof newPassword === 'string', 'New Password is required')
    assert.ok(typeof oldPassword === 'string', 'Old Password is required')

    const adm = await this._getAdminOrThrowError(email)

    if (!(await verify(oldPassword, adm.password))) {
      throw new UserError('INVALID_PASSWORD')
    }

    const password = await hash(newPassword, this.conf.hashSalt)

    return new Promise((resolve, reject) => {
      this.db.run(
        `UPDATE ${tableName} SET password = ? WHERE id = ?`,
        [password, adm.id],
        function (err) {
          if (err) return reject(err)

          resolve(true)
        }
      )
    })
  }

  async resetAdminPassword (email, newPassword, passwordResetToken) {
    assert.ok(this.conf.useDB, 'Cannot add admins if DB is not available')

    assert.ok(typeof email === 'string', 'Email is required')
    assert.ok(typeof newPassword === 'string', 'New Password is required')

    const admin = await this._getAdmin(email)
    if (!admin) throw new UserError('ADMIN_ACCOUNT_DOES_NOT_EXIST_OR_IS_NOT_ACTIVE')
    if (admin.passwordResetToken !== passwordResetToken) throw new UserError('INVALID_passwordResetToken')
    const expiryDate = new Date(admin.passwordResetSentAt)
    expiryDate.setDate(expiryDate.getDate() + 1)
    if (Date.now() > expiryDate) throw new UserError('RESET_LINK_EXPIRED')

    const password = await hash(newPassword, this.conf.hashSalt)

    return new Promise((resolve, reject) => {
      this.db.run(
        `UPDATE ${tableName} SET password = ? WHERE id = ?`,
        [password, admin.id],
        function (err) {
          if (err) return reject(err)

          resolve(true)
        }
      )
    })
  }

  async removeAdmin (idOrEmail) {
    assert.ok(this.conf.useDB, 'Cannot remove admins if DB is not available')

    return new Promise((resolve, reject) => {
      this.db.serialize(() => {
        const statement = this.db.prepare(`DELETE FROM ${tableName} WHERE id = ? OR LOWER(email) = ?`)
        statement.run([idOrEmail, `${idOrEmail}`.toLowerCase()])
        statement.finalize(err => {
          if (err) return reject(err)

          resolve(idOrEmail)
        })
      })
    })
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

  async checkAdmHasFetchMotivationsPrivilege (adminEmail) {
    const admin = await this._getAdmin(adminEmail)
    if (!admin) throw new Error('Searched admin was not found')

    return !!(admin.level === 0 || admin.fetchMotivationsPrivilege)
  }

  _checkIfAdminDbHasData () {
    return new Promise((resolve, reject) => {
      const query = `SELECT EXISTS(SELECT 1 FROM ${tableName}) as exist`
      this.db.get(query, (err, row) => {
        if (err) return reject(err)
        resolve(row?.exist)
      })
    })
  }

  /**
   * @param { string } email
   * @returns { BaseAdminT & { timestamp: Date, active: boolean } }
   */
  async getAdmin (email, active = true) {
    const admin = await this._getAdmin(email, active)
    const displayKeys = ['email', 'level', 'blockPrivilege', 'company',
      'analyticsPrivilege', 'manageAdminsPrivilege', 'fetchMotivationsPrivilege', 'readOnly', 'active', 'timestamp', ...SHOULD_STRINGIFY]

    if (this.conf.useDB && admin) {
      SHOULD_STRINGIFY.forEach(ss => {
        if (admin[ss]) admin[ss] = admin[ss] ? JSON.parse(admin[ss]) : null
      })
    }

    return admin
      ? _.pick(admin, displayKeys)
      : admin
  }

  /**
   * Retrieves admin given an email address.
   * @param {string} email - Email address of the admin to be retrieved.
   * @param {boolean} [active = true] -  Flag to be used in case we want to fetch the admin regardless of being active or not.
   * @throws {UserError} If no admin is found, this exception is thrown.
   * @returns 
   */
  async _getAdminOrThrowError (email, active = true) {
    const admin = await this._getAdmin(email, active)
    if (!admin) throw new UserError('ADMIN_ACCOUNT_DOES_NOT_EXIST_OR_IS_NOT_ACTIVE')
    return admin
  }

  async _getAdmin (email, active = true) {
    if (!email) return false

    return this.conf.useDB
      ? this._getAdminFromDB(email, active)
      : this._getAdminFromConfig(email)
  }

  async _getAdminFromDB (email, active) {
    return new Promise((resolve, reject) => {
      const query = active
        ? `SELECT * FROM ${tableName} WHERE LOWER(email) = ? AND active = 1`
        : `SELECT * FROM ${tableName} WHERE LOWER(email) = ?`

      this.db.get(query, [email.toLowerCase()], (err, row) => {
        if (err) return reject(err)
        resolve(row)
      })
    })
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
      ? this._getAdminEmailsFromDB(active, company)
      : this._getAdminEmailsFromConfig(company)
  }

  async _getAdminEmailsFromDB (active, company) {
    return new Promise((resolve, reject) => {
      const whereClause = [['active', active && 1], ['company', company && `'${company}'`]].reduce((query, prop) => {
        if (prop[1]) {
          if (query.length) {
            query += ' AND '
          }
          query += `${prop[0]} = ${prop[1]}`
        }
        return query
      }, '')

      const query = active || company
        ? `SELECT LOWER(email) AS email FROM ${tableName} WHERE ${whereClause} ORDER BY email ASC`
        : `SELECT LOWER(email) AS email FROM ${tableName} ORDER BY email ASC`

      this.db.all(query, [], (err, rows) => {
        if (err) return reject(err)
        resolve((rows || []).map(row => row.email))
      })
    })
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

  /**
   * Creates or update a daily limit configuration for a given combination of admin level and daily limit category
   * @param {number} level - The admin level
   * @param {DailyLimitCategory} category - The daily limit category
   * @param {DailyLimitConfig} config - The configuration values for the admin level and category daily limit
   * @throws {UserError} In the following cases:
   * - admin level is not integer or it's not between 0 and 4 inclusive
   * - category is neither `opened` nor `displayed`
   * - `config.alert` and `config.block` are not provided, or at least one of them is provided but not integer or it's integer but not positive
   * - the daily limit for the given admin level and category exists but `config.alert` and `config.block` are not provided
   * @returns {Promise<boolean>} Resolves to `true` if daily limit configuration is created/updated successfully. Otherwise, triggers a rejection.
   */
  async setAdminLevelDailyLimit (level, category, config) {
    this._validateAdminLevel(level)
    this._validateDailyLimitCategory(category)

    const existingLevelDailyLimit = await this.getAdminLevelDailyLimit(level, category)

    const { alert, block } = config ?? {}

    if (isNil(alert) && isNil(block)) throw new UserError('Neither alert nor block values are provided')
    if (!existingLevelDailyLimit && ((!isNil(alert) && isNil(block)) || (isNil(alert) && !isNil(block)))) throw new UserError('When creating an admin level daily limit both alert and block must be provided')
    if (!isNil(alert) && (!Number.isInteger(alert) || alert < 0)) throw new UserError('When alert value is provided, must be integer and greater or equal to zero')
    if (!isNil(block) && (!Number.isInteger(block) || block < 0)) throw new UserError('When block value is provided, must be integer and greater or equal to zero')

    const cb = (resolve, reject) => function (err) {
      if (err) return reject(err)
      resolve(true)
    }

    if (existingLevelDailyLimit) {
      const valuesToUpdate = {}
      if (!isNil(alert)) valuesToUpdate.alert = alert
      if (!isNil(block)) valuesToUpdate.block = block
      const fields = Object.keys(valuesToUpdate)

      return new Promise((resolve, reject) => {
        this.db.run(
          `UPDATE ${DB_TABLES.ADMIN_LEVEL_DAILY_LIMITS} SET ${fields.join(' = ?, ')} = ? WHERE level = ? AND category = ?`,
          Object.values(valuesToUpdate).concat([level, category]),
          cb(resolve, reject)
        )
      })
    } else {
      return new Promise((resolve, reject) => {
        this.db.run(
          `INSERT INTO ${DB_TABLES.ADMIN_LEVEL_DAILY_LIMITS} (level, category, alert, block) VALUES (?, ?, ?, ?)`,
          [level, category, alert, block],
          cb(resolve, reject)
        )
      })
    }
  }

  /**
   * Remove all daily limits records associated to an admin level
   * @param {AdminLevel} level - The admin level value that we want to remove all its daily limit records from
   * @returns {Promise<boolean>} Resolves to `true` in case we remove all the records successfully. Throws an error in case something goes wrong.
   */
  async removeAdminLevelDailyLimits (level) {
    this._validateAdminLevel(level)
    return new Promise((resolve, reject) => {
      this.db.serialize(() => {
        const statement = this.db.prepare(`DELETE FROM ${DB_TABLES.ADMIN_LEVEL_DAILY_LIMITS} WHERE level = ?`)
        statement.run([level])
        statement.finalize(err => {
          if (err) return reject(err)
          resolve(true)
        })
      })
    })
  }

  /**
   * Retrieves a daily limit config associated to an admin level and a daily limit category
   * @param {number} level - The admin level
   * @param {DailyLimitCategory} category - The daily limit category
   * @throws {UserError} In the following cases:
   * - admin level is not integer or it's not between 0 and 4 inclusive
   * - category is neither `opened` nor `displayed`
   * @returns {Promise<DailyLimitConfig | null>} Resolves to a `DailyLimitConfig` object if there is a daily limit associated to the provided admin level and category, or null if there is nothing saved yet in the database. Otherwise, triggers a rejection.
   */
  async getAdminLevelDailyLimit (level, category) {
    this._validateAdminLevel(level)
    this._validateDailyLimitCategory(category)

    return new Promise((resolve, reject) => {
      this.db.get(
        `SELECT alert, block FROM ${DB_TABLES.ADMIN_LEVEL_DAILY_LIMITS} WHERE level = ? AND category = ? LIMIT 1`,
        [level, category],
        function (err, row) {
          if (err) return reject(err)
          resolve(row || null)
        }
      )
    })
  }

  /**
   * Retrieves all daily limit records associated to a given admin level
   * @param {number} level - The admin level
   * @throws {UserError} In the following cases:
   * - admin level is not integer or it's not between 0 and 4 inclusive
   * @returns {Promise<AdminLevelDailyLimitConfigsByCategory | null>} Resolves to a `AdminLevelDailyLimitConfigsByCategory` object. If an error is detected, triggers an exception.
   */
  async getDailyLimitsByAdminLevel (level) {
    this._validateAdminLevel(level)

    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT category, alert, block FROM ${DB_TABLES.ADMIN_LEVEL_DAILY_LIMITS} WHERE level = ?`,
        [level],
        function (err, rows) {
          if (err) return reject(err)
          if (!rows?.length) resolve(null)
          resolve(rows.reduce((acc, curr) => {
            acc[curr.category] = pick(curr, ['alert', 'block'])
            return acc
          }, {}))
        }
      )
    })
  }

  /**
   * Retrieves all daily limit records associated to a given category
   * @param {DailyLimitCategory} category - The daily limit category
   * @throws {UserError} In the following cases:
   * - category is neither `opened` nor `displayed`
   * @returns {Promise<AdminLevelDailyLimitConfigsByAdminLevel>} Resolves to a `AdminLevelDailyLimitConfigsByAdminLevel` object. If an error is detected, triggers an exception.
   */
  async getDailyLimitsByCategory (category) {
    this._validateDailyLimitCategory(category)

    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT level, alert, block FROM ${DB_TABLES.ADMIN_LEVEL_DAILY_LIMITS} WHERE category = ?`,
        [category],
        function (err, rows) {
          if (err) return reject(err)
          resolve((rows ?? []).reduce((acc, curr) => {
            acc[curr.level] = pick(curr, ['alert', 'block'])
            return acc
          }, {}))
        }
      )
    })
  }

  /**
   * Guard method for validating a given number is a valid admin level
   * @param {number} level - Value representing the admin level to evaluate
   * @throws {UserError} If `level` is not a valid `AdminLevel`
   */
  _validateAdminLevel (level) {
    if (!Number.isInteger(level) || !_.inRange(level, MIN_ADMIN_LEVEL, MAX_ADMIN_LEVEL + 1)) throw new UserError(`"${level}" as admin level is invalid`)
  }

  /**
   * Guard method for validating a given string is a valid daily limit category
   * @param {string} category - Value representing the daily limit category to evaluate
   * @throws {UserError} If `category` is not a valid `DailyLimitCategory`
   */
  _validateDailyLimitCategory (category) {
    if (!VALID_DAILY_LIMIT_CATEGORIES.some(c => c === category)) throw new UserError(`"${category}" as daily limit category value is invalid`)
  }

  /**
   * Retrieves the daily limit config associated to an admin
   * @param {string} adminUserEmail - The email address associated to the admin.
   * @throws {UserError} If no admin associated to the provided email address is found, this exception is thrown.
   * @returns {DailyLimitConfigsByCategory|null} Returns the fully fleshed daily limit config object associated to the admin.
   * If it hasn't been set yet, then returns the daily limit config object associated to the admin level. If this does not exist
   * either then return `null`.
   */
  async getAdminUserDailyLimitConfig (adminUserEmail) {
    const admin = await this.getAdmin(adminUserEmail)
    if (!admin) return null
    const val = admin.dailyLimitConfig
    if (val) return val
    return this.getDailyLimitsByAdminLevel(admin.level)
  }

  /**
   * Removes the daily limit config associated to an admin.
   * @param {string} adminUserEmail - The email address associated to the admin. 
   * @throws {UserError} If no admin associated to the provided email address is found, this exception is thrown.
   * @returns {Promise<boolean>} Resolves to `true` if daily limit configuration is removed successfully. Otherwise, triggers a rejection.
   */
  async removeAdminUserDailyLimitConfig (adminUserEmail) {
    const adm = await this._getAdminOrThrowError(adminUserEmail)
    return new Promise((resolve, reject) => {
      this.db.run(
        `UPDATE ${tableName} SET dailyLimitConfig = ? WHERE id = ?`,
        [null, adm.id],
        function (err) {
          if (err) return reject(err)
          resolve(true)
        }
      )
    })
  }
}

module.exports = GoogleAuth
