'use strict'

const _ = require('lodash')
const Base = require('bfx-facs-base')
const uuidv4 = require('uuid/v4')
const {google} = require('googleapis')

class GoogleAuth extends Base {
  constructor (caller, opts, ctx) {
    super(caller, opts, ctx)

    this.name = 'auth-google'
    this._hasConf = true
    this.useRedis = opts.useRedis || false
    this.mongoFac = opts.mongoFac || ctx.dbMongo_m0
    this.redisFac = opts.redisFac || ctx.redis_gc0

    this.init()

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
    const {valid, level} = this.basicAuthAdmLogCheck(params.username, params.password)
    return (valid)
      ? this._createAdminToken(params.username, ip, level, cb)
      : cb(new Error('AUTH_FAC_LOGIN_INCORRECT_USERNAME_PASSWORD'))
  }

  async _loginAdminGoogle (params, ip, cb) {
    try {
      const email = await this.googleEmailFromToken(params)
      const {valid, level} = this._validAdminUserGoogleEmail(email)
      return (valid)
        ? this._createAdminToken(email, ip, level, cb)
        : cb(new Error('AUTH_FAC_ONLY_BITFINEX_ACCOUNTS_ARE_ALLOW'))
    } catch (e) {
      cb(new Error('AUTH_FAC_INCORRECT_GOOGLE_TOKEN'))
    }
  }

  async _createAdminToken (user, ip, level, cb) {
    const username = user
    const token = 'ADM-' + uuidv4()
    const exp = new Date()
    exp.setHours(exp.getHours() + 8)
    const query = { username, token, ip, level, expires_at: exp }
    try {
      await this._createUniqueAndExpireDbToken(query)
      return cb(null, { username, token, level, expires_at: exp })
    } catch (e) {
      return cb(new Error('AUTH_FAC_ADMIN_TOKEN_CREATE_ERROR'))
    }
  }

  _tokenKey (query) {
    return `adminTokens:${query.token}:${query.ip}`
  }

  _createUniqueAndExpireDbToken (query) {
    const ctx = this.caller
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
    const ctx = this.caller
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
    const {clientId, clientSecret} = this.conf
    return new google.auth.OAuth2(
      clientId,
      clientSecret
    )
  }

  googleEmailFromToken (token) {
    return new Promise(async (resolve, reject) => {
      const oAuth2Client = await this._getOAuth2Client()
      oAuth2Client.setCredentials(token)
      const oauth2 = google.oauth2({version: 'v2', auth: oAuth2Client})
      oauth2.userinfo.v2.me.get(
        (err, data) => {
          if (err) reject(new Error('AUTH_FAC_ERROR_ASK_EMAIL:' + err.toString()))
          else resolve(data.data.email)
        })
    })
  }

  _whiteListEmail (email) {
    const { ADM_USERS } = this.conf
    let valid = false
    let level
    _.forEach(ADM_USERS, user => {
      if (user.email === email) {
        valid = true
        if (valid) level = user.level
        return false
      }
    })
    return { valid, level }
  }

  basicAuthAdmLogCheck (email, password) {
    const { ADM_USERS } = this.conf
    let valid = false
    let level
    _.forEach(ADM_USERS, user => {
      if (user.email === email && user.password) {
        valid = user.password === password
        if (valid) level = user.level
        return false
      }
    })
    return { valid, level }
  }

  checkAdmAccessLevel (admin, level) {
    let valid = false
    if (admin) {
      const { ADM_USERS } = this.conf
      _.forEach(ADM_USERS, user => {
        if (user.email === admin) {
          valid = user.level <= level
          return false
        }
      })
    }
    return valid
  }
}

module.exports = GoogleAuth
