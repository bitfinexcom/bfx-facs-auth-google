'use strict'

const assert = require('assert')
const crypto = require('crypto')
const { isNil, isBoolean } = require('@bitfinex/lib-js-util-base')
const BaseRepository = require('./repository')
const { UserError } = require('../errors')

/**
 * @typedef {{
 *  email: string,
 *  level: number,
 *  readOnly?: boolean,
 *  blockPrivilege?: boolean,
 *  analyticsPrivilege?: boolean,
 *  manageAdminsPrivilege?: boolean,
 *  casesPrivilege?: boolean,
 *  fetchMotivationsPrivilege?: boolean,
 *  passwordResetToken?: string,
 *  passwordResetSentAt?: Date,
 *  company?: string,
 *  forms?: string[],
 *  whitelistedIps?: string[]
 * }} BaseAdminT
 * @typedef { BaseAdminT & { password: string }} AddAdminT
 * @typedef { BaseAdminT & {
 *  active: boolean,
 *  id: number
 * }} AddedAdminT
 */

function hash (password, salt = '') {
  const computedSalt = salt || crypto.randomBytes(8).toString('hex')
  const derivedKey = crypto.scryptSync(password, computedSalt, 64)
  return computedSalt + ':' + derivedKey.toString('hex')
}

function verify (password, hash) {
  const [salt, key] = hash.split(':')
  const derivedKey = crypto.scryptSync(password, salt, 64)
  return key === derivedKey.toString('hex')
}

function isValidDate (value) {
  const date = new Date(value)
  return !isNaN(date.getTime())
}

class AdminUserRepository extends BaseRepository {
  static tableName = 'admin_users'
  static FORMS_FIELD = 'forms'
  static JSON_FIELDS = [AdminUserRepository.FORMS_FIELD, 'whitelistedIps']

  static runSqlAtStart = [
    `CREATE TABLE IF NOT EXISTS ${AdminUserRepository.tableName} (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT,
      level INTEGER NOT NULL,
      active TINYINTEGER DEFAULT 1,
      readOnly TINYINTEGER,
      blockPrivilege TINYINTEGER,
      analyticsPrivilege TINYINTEGER,
      manageAdminsPrivilege TINYINTEGER,
      casesPrivilege TINYINTEGER,
      passwordResetToken TEXT,
      passwordResetSentAt DATETIME,
      company TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      ${AdminUserRepository.FORMS_FIELD} TEXT,
      whitelistedIps TEXT
    )`,
    `CREATE UNIQUE INDEX IF NOT EXISTS uidx_email ON ${AdminUserRepository.tableName}(email ASC)`
  ]

  /**
   *
   * @param {import('better-sqlite3').Database} db
   * @param {{useDb: boolean, hashSalt: string}} conf
   */
  constructor (db, conf) {
    super(db, AdminUserRepository.tableName, conf)
  }

  /**
   * @param { AddAdminT } user
   * @returns { AddedAdminT }
   */
  add (user) {
    const {
      email,
      password,
      level,
      readOnly,
      blockPrivilege,
      analyticsPrivilege,
      manageAdminsPrivilege,
      casesPrivilege,
      fetchMotivationsPrivilege,
      company,
      whitelistedIps
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

    if (casesPrivilege) {
      assert.ok(typeof casesPrivilege === 'boolean', 'casesPrivilege should be a boolean')
    }

    if (fetchMotivationsPrivilege) {
      assert.ok(typeof fetchMotivationsPrivilege === 'boolean', 'fetchMotivationsPrivilege should be a boolean')
    }

    if (company) {
      assert.ok(typeof company === 'string', 'company should be a string')
    }

    if (whitelistedIps !== undefined) {
      assert.ok(Array.isArray(whitelistedIps), 'whitelistedIps should be an array')
      whitelistedIps.forEach((ip) => {
        assert.ok(typeof ip === 'string', 'each whitelistedIps entry should be a string')
      })
    }

    const adm = this.getAdmin(email, false)
    if (adm) throw new UserError('ADMIN_ACCOUNT_EXISTS')

    user.password = password
      ? hash(password, this.conf.hashSalt)
      : null

    const data = {
      ...user,
      ...Object.fromEntries(
        Object.keys(user).map(key => [key, AdminUserRepository.JSON_FIELDS.includes(key) ? JSON.stringify(user[key]) : user[key]])
      )
    }
    const saved = super.add(data)

    return {
      email,
      level,
      readOnly,
      blockPrivilege,
      analyticsPrivilege,
      manageAdminsPrivilege,
      casesPrivilege,
      fetchMotivationsPrivilege,
      company,
      whitelistedIps,
      active: true,
      id: saved.id
    }
  }

  update (email, user) {
    const {
      password,
      level,
      readOnly,
      blockPrivilege,
      analyticsPrivilege,
      manageAdminsPrivilege,
      casesPrivilege,
      fetchMotivationsPrivilege,
      company,
      active,
      whitelistedIps,
      passwordResetToken,
      passwordResetSentAt
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

    if (casesPrivilege) {
      assert.ok(typeof casesPrivilege === 'boolean', 'casesPrivilege should be a boolean')
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

    if (whitelistedIps !== undefined) {
      assert.ok(Array.isArray(whitelistedIps), 'whitelistedIps should be an array')
      whitelistedIps.forEach((ip) => {
        assert.ok(typeof ip === 'string', 'each whitelistedIps entry should be a string')
      })
    }

    if (!isNil(passwordResetToken)) {
      assert.ok(typeof passwordResetToken === 'string', 'passwordResetToken should be a string')
    }

    if (!isNil(passwordResetSentAt)) {
      assert.ok(isValidDate(passwordResetSentAt), 'passwordResetSentAt should be a valid date')
    }

    const adm = this.getAdmin(email, !active)
    if (!adm) throw new UserError('ADMIN_ACCOUNT_DOES_NOT_EXIST_OR_IS_NOT_ACTIVE')

    const keys = Object.keys(user)
    const params = keys.map(key => {
      const value = AdminUserRepository.JSON_FIELDS.includes(key) ? JSON.stringify(user[key]) : user[key]
      return isBoolean(value) ? Number(value) : value
    }).concat(adm.id)
    this.db.prepare(`UPDATE ${this.tableName} SET ${keys.join(' = ?, ')} = ? WHERE id = ?`).run(...params)
    return this.db.prepare(`SELECT * FROM ${this.tableName} WHERE id = ?`).get(adm.id)
  }

  updatePassword (email, newPassword, oldPassword) {
    assert.ok(typeof email === 'string', 'Email is required')
    assert.ok(typeof newPassword === 'string', 'New Password is required')
    assert.ok(typeof oldPassword === 'string', 'Old Password is required')

    const adm = this.getAdmin(email)
    if (!adm) throw new UserError('ADMIN_ACCOUNT_DOES_NOT_EXIST_OR_IS_NOT_ACTIVE')

    if (!(verify(oldPassword, adm.password))) throw new UserError('INVALID_PASSWORD')

    const password = hash(newPassword, this.conf.hashSalt)

    this.db.prepare(`UPDATE ${this.tableName} SET password = ? WHERE id = ?`).run(password, adm.id)
    return true
  }

  resetPassword (email, newPassword, passwordResetToken) {
    assert.ok(typeof email === 'string', 'Email is required')
    assert.ok(typeof newPassword === 'string', 'New Password is required')

    const admin = this.getAdmin(email)
    if (!admin) throw new UserError('ADMIN_ACCOUNT_DOES_NOT_EXIST_OR_IS_NOT_ACTIVE')
    if (admin.passwordResetToken !== passwordResetToken) throw new UserError('INVALID_passwordResetToken')

    const expiryDate = new Date(admin.passwordResetSentAt)
    expiryDate.setDate(expiryDate.getDate() + 1)
    if (Date.now() > expiryDate) throw new UserError('RESET_LINK_EXPIRED')

    const password = hash(newPassword, this.conf.hashSalt)
    this.db.prepare(`UPDATE ${this.tableName} SET password = ? WHERE id = ?`).run(password, admin.id)
    return true
  }

  /**
   * @param { string|number } emailOrId - Identifier used for searching the admin, it can be either the admin email address or its database id.
   * @param { boolean } [active=true] - Flag for considering only the active users, it is `true` by default. If `false`, it will search through inactive users too.
   * @param { boolean } [id=false] - Flag for searching as well by id criterion, it's `false` by default. If `true`, enables the mentioned behavior.
   * @returns { BaseAdminT & { timestamp: Date, active: boolean } }
   */
  getAdmin (emailOrId, active = true, id = false) {
    const identifierCondition = id
      ? '(LOWER(email) = ? OR id = ?)'
      : 'LOWER(email) = ?'

    const query = active
      ? `SELECT * FROM ${this.tableName} WHERE ${identifierCondition} AND active = 1`
      : `SELECT * FROM ${this.tableName} WHERE ${identifierCondition}`

    const params = [String(emailOrId).toLowerCase()]
    if (id) params.push(emailOrId)
    return this.db.prepare(query).get(...params)
  }

  /**
   *
   * @param {boolean?} active
   * @param {string?} company
   * @returns {Promise<string[]>}
   */
  async getAdminEmails (active, company) {
    return new Promise((resolve, reject) => {
      let whereClause = ''
      const params = []
      if (active) {
        whereClause += 'active =?'
        params.push(1)
      }
      if (company) {
        if (whereClause.length) {
          whereClause += ' AND '
        }
        whereClause += 'company =?'
        params.push(company)
      }

      const query = active || company
        ? `SELECT LOWER(email) AS email FROM ${this.tableName} WHERE ${whereClause} ORDER BY email ASC`
        : `SELECT LOWER(email) AS email FROM ${this.tableName} ORDER BY email ASC`

      this.db.all(query, params, (err, rows) => {
        if (err) return reject(err)
        resolve((rows || []).map(row => row.email))
      })
    })
  }

  /**
   *
   * @returns {Boolean}
   */
  doesAdminDbHaveData () {
    const query = `SELECT EXISTS(SELECT 1 FROM ${this.tableName}) as exist`
    return this.db.prepare(query).get()?.exist
  }

  async remove (idOrEmail) {
    return new Promise((resolve, reject) => {
      this.db.serialize(() => {
        const statement = this.db.prepare(`DELETE FROM ${this.tableName} WHERE id = ? OR LOWER(email) = ?`)
        statement.run([idOrEmail, `${idOrEmail}`.toLowerCase()])
        statement.finalize(err => {
          if (err) return reject(err)

          resolve(idOrEmail)
        })
      })
    })
  }
}

module.exports = AdminUserRepository
