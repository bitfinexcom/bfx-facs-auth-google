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

const FORMS_FIELD = 'forms'

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

const tableName = 'admin_users'
/**
 * @typedef {{
 *  email: string,
 *  level: number,
 *  readOnly?: boolean,
 *  blockPrivilege?: boolean,
 *  analyticsPrivilege?: boolean,
 *  manageAdminsPrivilege?: boolean,
 *  passwordResetToken?: string,
 *  passwordResetSentAt?: Date,
 *  company?: string,
 *  forms?: string[]
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
 * @typedef { AddedAdminT & {
 *  username: string,
 *  token: string,
 *  expires_at: Date
 * }} LoginResp
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
        ${FORMS_FIELD} TEXT
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

    if (!user || !google) {
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

  async _loginAdminGoogle (params, ip, cb) {
    try {
      const email = await this.googleEmailFromToken(params)
      const { valid, level, extra } = await this._validAdminUserGoogleEmail(email)
      return (valid)
        ? this._createAdminToken(email, ip, level, extra, cb)
        : cb(new Error('AUTH_FAC_ONLY_BITFINEX_ACCOUNTS_ARE_ALLOW'))
    } catch (e) {
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

  _getOAuth2Client () {
    const { clientId, clientSecret } = this.conf.google
    return new google.auth.OAuth2(
      clientId,
      clientSecret
    )
  }

  async googleEmailFromToken (token) {
    const oAuth2Client = await this._getOAuth2Client()
    if (token?.credential) {
      const ticket = await oAuth2Client.verifyIdToken({
        idToken: token.credential
      })

      const payload = ticket.getPayload()
      return payload.email
    }
    oAuth2Client.setCredentials(token)
    const oauth2 = google.oauth2({ version: 'v2', auth: oAuth2Client })

    return new Promise((resolve, reject) => {
      oauth2.userinfo.get(
        (err, data) => {
          if (err) reject(new Error('AUTH_FAC_ERROR_ASK_EMAIL:' + err.toString()))
          else resolve(data && data.data && data.data.email)
        })
    })
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

    const tasks = admins.map(async (admin) => {
      const { email } = admin
      const adm = await this._getAdmin(email)
      if (adm) return adm

      return this.addAdmin(admin)
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
      company
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

    if (company) {
      assert.ok(typeof company === 'string', 'company should be a string')
    }

    const adm = await this._getAdmin(email, false)
    if (adm) throw new Error('ADMIN_ACCOUNT_EXISTS')

    const hashedPassword = password
      ? await hash(password, this.conf.hashSalt)
      : null

    user.password = hashedPassword

    return new Promise((resolve, reject) => {
      const keys = Object.keys(user)

      this.db.run(
        `INSERT INTO ${tableName} (${keys.join(', ')}) VALUES (${Array(keys.length).fill('?').join(', ')})`,
        keys.map(key => key === FORMS_FIELD ? JSON.stringify(user[key]) : user[key]),
        function (err) {
          if (err) return reject(err)

          resolve({
            email,
            level,
            readOnly,
            blockPrivilege,
            analyticsPrivilege,
            manageAdminsPrivilege,
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
      company,
      active
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

    if (company) {
      assert.ok(typeof company === 'string', 'company should be a string')
    }

    if (active) {
      assert.ok(typeof active === 'boolean', 'active should be a boolean')
    }

    const adm = await this._getAdmin(email)
    if (!adm) throw new UserError('ADMIN_ACCOUNT_DOES_NOT_EXIST_OR_IS_NOT_ACTIVE')

    return new Promise((resolve, reject) => {
      const keys = Object.keys(user)

      this.db.run(
        `UPDATE ${tableName} SET ${keys.join(' = ?, ')} = ? WHERE id = ?`,
        keys.map(key => user[key]).concat(adm.id),
        function (err) {
          if (err) return reject(err)

          resolve(user)
        }
      )
    })
  }

  async updateAdminPassword (email, newPassword, oldPassword) {
    assert.ok(this.conf.useDB, 'Cannot add admins if DB is not available')

    assert.ok(typeof email === 'string', 'Email is required')
    assert.ok(typeof newPassword === 'string', 'New Password is required')
    assert.ok(typeof oldPassword === 'string', 'Old Password is required')

    const adm = await this._getAdmin(email)
    if (!adm) throw new UserError('ADMIN_ACCOUNT_DOES_NOT_EXIST_OR_IS_NOT_ACTIVE')

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
  async resetAdminPassword(email, newPassword, passwordResetToken) {
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

  /**
   * @param { string } email
   * @returns { BaseAdminT & { timestamp: Date, active: boolean } }
   */
  async getAdmin (email, active = true) {
    const admin = await this._getAdmin(email, active)
    const displayKeys = ['email', 'level', 'blockPrivilege', 'company',
      'analyticsPrivilege', 'manageAdminsPrivilege', 'readOnly', 'active', 'timestamp', FORMS_FIELD]

    if (this.conf.useDB && admin && admin[FORMS_FIELD]) {
      admin[FORMS_FIELD] = JSON.parse(admin[FORMS_FIELD])
    }

    return admin
      ? _.pick(admin, displayKeys)
      : admin
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

  async getAdminEmails (active = true) {
    return this.conf.useDB
      ? this._getAdminEmailsFromDB(active)
      : this._getAdminEmailsFromConfig()
  }

  async _getAdminEmailsFromDB (active) {
    return new Promise((resolve, reject) => {
      const query = active
        ? `SELECT LOWER(email) AS email FROM ${tableName} WHERE active = 1 ORDER BY email ASC`
        : `SELECT LOWER(email) AS email FROM ${tableName} ORDER BY email ASC`

      this.db.all(query, [], (err, rows) => {
        if (err) return reject(err)
        resolve((rows || []).map(row => row.email))
      })
    })
  }

  async _getAdminEmailsFromConfig () {
    const admins = this.conf.ADM_USERS || []
    return admins.map(
      u => u.email.toLowerCase()
    )
  }
}

module.exports = GoogleAuth
