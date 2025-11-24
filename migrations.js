'use strict'

const TABLES = {
  ADMIN_USERS: 'admin_users',
  DAILY_LIMITS: 'daily_limits'
}

const migrations = [
  (_this, cb) => {
    _this.db.all(`PRAGMA table_info(${TABLES.ADMIN_USERS})`, [], (err, rows) => {
      if (err) return cb(err)
      if (rows?.find(row => row.name === 'manageAdminsPrivilege')) return cb()

      _this.db.run(`
        ALTER TABLE ${TABLES.ADMIN_USERS}
        ADD manageAdminsPrivilege TINYINTEGER
      `, cb)
    })
  },
  (_this, cb) => {
    _this.db.all(`PRAGMA table_info(${TABLES.ADMIN_USERS})`, [], (err, rows) => {
      if (err) return cb(err)
      if (rows?.find(row => row.name === 'forms')) return cb()

      _this.db.run(`
        ALTER TABLE ${TABLES.ADMIN_USERS}
        ADD forms TEXT
      `, cb)
    })
  },
  (_this, cb) => {
    _this.db.all(`PRAGMA table_info(${TABLES.ADMIN_USERS})`, [], (err, rows) => {
      if (err) return cb(err)
      if (rows?.find(row => row.name === 'passwordResetSentAt')) return cb()

      _this.db.run(`
        ALTER TABLE ${TABLES.ADMIN_USERS}
        ADD passwordResetSentAt DATETIME
      `, cb)
    })
  },
  (_this, cb) => {
    _this.db.all(`PRAGMA table_info(${TABLES.ADMIN_USERS})`, [], (err, rows) => {
      if (err) return cb(err)
      if (rows?.find(row => row.name === 'passwordResetToken')) return cb()

      _this.db.run(`
        ALTER TABLE ${TABLES.ADMIN_USERS}
        ADD passwordResetToken TEXT
      `, cb)
    })
  },
  (_this, cb) => {
    _this.db.all(`PRAGMA table_info(${TABLES.ADMIN_USERS})`, [], (err, rows) => {
      if (err) return cb(err)
      if (rows?.find(row => row.name === 'fetchMotivationsPrivilege')) return cb()

      _this.db.run(`
        ALTER TABLE ${TABLES.ADMIN_USERS}
        ADD fetchMotivationsPrivilege BOOLEAN
      `, cb)
    })
  }
]

module.exports = migrations
