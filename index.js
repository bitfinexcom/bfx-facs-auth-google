'use strict'

const Base = require('bfx-facs-base')
const uuidv4 = require('uuid/v4')
const { google } = require('googleapis')

class GoogleAuth extends Base {
  constructor (caller, opts, ctx) {
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

  loginAdmin (args, cb) {
    const { user, google, ip } = args

    const complete = (user)
      ? ['username', 'password'].every(k => k in user)
      : ['access_token', 'token_type', 'expiry_date'].every(k => k in google)
    if (!complete) return cb(new Error('AUTH_FAC_LOGIN_KEYS_MISSING'))

    return (user)
      ? this._loginAdminPass(user, ip, cb)
      : this._loginAdminGoogle(google, ip, cb)
  }

  _loginAdminPass (params, ip, cb) {
    const {
      valid, level, extra
    } = this.basicAuthAdmLogCheck(params.username, params.password)

    return (valid)
      ? this._createAdminToken(params.username, ip, level, extra, cb)
      : cb(new Error('AUTH_FAC_LOGIN_INCORRECT_USERNAME_PASSWORD'))
  }

  async _loginAdminGoogle (params, ip, cb) {
    try {
      const email = await this.googleEmailFromToken(params)
      const { valid, level, extra } = this._validAdminUserGoogleEmail(email)
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

  _validAdminUserGoogleEmail (mail) {
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

  googleEmailFromToken (token) {
    return new Promise(async (resolve, reject) => {
      const oAuth2Client = await this._getOAuth2Client()
      oAuth2Client.setCredentials(token)
      const oauth2 = google.oauth2({ version: 'v2', auth: oAuth2Client })
      oauth2.userinfo.get(
        (err, data) => {
          if (err) reject(new Error('AUTH_FAC_ERROR_ASK_EMAIL:' + err.toString()))
          else resolve(data.data.email)
        })
    })
  }

  _whiteListEmail (sentEmail) {
    const admin = this._getAdmin(sentEmail)

    if (!admin) return { valid: false }

    const { email, password, level, ...extra } = admin

    return {
      valid: true,
      level,
      extra
    }
  }

  basicAuthAdmLogCheck (sentEmail, sentPassword) {
    const admin = this._getAdmin(sentEmail)

    if (!(
      admin &&
      admin.password && // password cant be empty or false
      admin.password === sentPassword
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

  checkAdmAccessLevel (adminEmail, level) {
    const admin = this._getAdmin(adminEmail)
    const valid = !!admin && admin.level <= level
    return valid
  }

  checkAdmIsReadOnly (adminEmail) {
    const admin = this._getAdmin(adminEmail)
    if (!admin) throw new Error('Searched admin was not found')

    return !!admin.readOnly
  }

  checkAdmHasBlockPrivilege (adminEmail) {
    const admin = this._getAdmin(adminEmail)
    if (!admin) throw new Error('Searched admin was not found')

    return !!(admin.level === 0 || admin.blockPrivilege)
  }

  _getAdmin (email) {
    if (!email) return false

    const admins = this.conf.ADM_USERS

    for (const adm of admins) {
      if (adm.email === email) return adm
    }

    return false
  }
}

module.exports = GoogleAuth
