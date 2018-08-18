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

    this.init()
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
    const valid = this.basicAuthAdmLogCheck(params.username, params.password)
    return (valid)
      ? this._createAdminToken(params.username, ip, cb)
      : cb(new Error('KYC_LOGIN_INCORRECT_USERNAME_PASSWORD'))
  }

  async _loginAdminGoogle (params, ip, cb) {
    try {
      const email = await this.googleEmailFromToken(params)
      const valid = this._validAdminUserGoogleEmail(email)
      return (valid)
        ? this._createAdminToken(email, ip, cb)
        : cb(new Error('AUTH_FAC_ONLY_BITFINEX_ACCOUNTS_ARE_ALLOW'))
    } catch (e) {
      cb(new Error('AUTH_FAC_INCORRECT_GOOGLE_TOKEN'))
    }
  }

  async _createAdminToken (user, ip, cb) {
    const username = user.replace('@bitfinex.com', '')
    const token = 'ADM-' + uuidv4()
    const expiresAt = new Date()
    expiresAt.setHours(expiresAt.getHours() + 8)
    const expiresAtSeconds = 28800
    const query = { username, token, ip, expiresAt, expiresAtSeconds }
    try {
      await this._createUniqueAndExpireDbToken(query)
      return cb(null, { username, token, expiresAt })
    } catch (e) {
      return cb(new Error('AUTH_FAC_ADMIN_TOKEN_CREATE_ERROR'))
    }
  }

  _tokenKey (query) {
    return `admtokens:${query.token}:${query.ip}`
  }

  _createUniqueAndExpireDbToken (query) {
    const ctx = this.caller
    if (ctx.dbMongo_m0) { // kyc-ui
      const mc = ctx.dbMongo_m0.db
      const collection = 'admTokens'
      return new Promise((resolve, reject) => {
        mc.collection(collection)
          .insertOne(query, (err, res) => {
            if (err) return reject(err)
            resolve()
          })
      })
    } else { // ethfinex-admin-ui
      const key = this._tokenKey(query)
      ctx.redis_gc0.cli_rw.multi([
        ['set', key, query],
        ['expire', key, query.expiresAtSeconds]
      ])
    }
  }

  _validAdminUserGoogleEmail (mail) {
    return this._whiteListEmail(mail)
  }

  preAdminTokenCheck (authToken) {
    return (authToken && authToken.length === 2)
      ? authToken[0].startsWith('ADM')
      : false
  }

  async checkAdminRedis (authToken) {
    const ctx = this.ctx
    const preCheck = this.preAdminTokenCheck(authToken)
    if (!preCheck) return false
    const token = authToken[0]
    const ip = authToken[1].ip
    const key = this._tokenKey({ token, ip })
    const data = await ctx.redis_gc0.cli_rw.get(key)
    return !!data && data.username && data.username.length > 0
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
