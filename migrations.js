'use strict'

const tableName = 'admin_users'

const migrations = [
  (_this, cb) => {
    _this.db.all(`PRAGMA table_info(${tableName})`, [], (err, rows) => {
      if (err) return cb(err)
      if (rows?.find(row => row.name === 'manageAdminsPrivilege')) return cb()

      _this.db.run(`
        ALTER TABLE ${tableName}
        ADD manageAdminsPrivilege TINYINTEGER
      `, cb)
    })
  },
  (_this, cb) => {
    _this.db.all(`PRAGMA table_info(${tableName})`, [], (err, rows) => {
      if (err) return cb(err)
      if (rows?.find(row => row.name === 'forms')) return cb()

      _this.db.run(`
        ALTER TABLE ${tableName}
        ADD forms TEXT
      `, cb)
    })
  },
  (_this, cb) => {
    _this.db.all(`PRAGMA table_info(${tableName})`, [], (err, rows) => {
      if (err) return cb(err)
      if (rows?.find(row => row.name === 'passwordResetSentAt')) return cb()

      _this.db.run(`
        ALTER TABLE ${tableName}
        ADD passwordResetSentAt DATETIME
      `, cb)
    })
  },
  (_this, cb) => {
    _this.db.all(`PRAGMA table_info(${tableName})`, [], (err, rows) => {
      if (err) return cb(err)
      if (rows?.find(row => row.name === 'passwordResetToken')) return cb()

      _this.db.run(`
        ALTER TABLE ${tableName}
        ADD passwordResetToken TEXT
      `, cb)
    })
  },
  (_this, cb) => {
    _this.db.all(`PRAGMA table_info(${tableName})`, [], (err, rows) => {
      if (err) return cb(err)
      if (rows?.find(row => row.name === 'fetchMotivationsPrivilege')) return cb()

      _this.db.run(`
        ALTER TABLE ${tableName}
        ADD fetchMotivationsPrivilege BOOLEAN
      `, cb)
    })
  }
]

module.exports = migrations
