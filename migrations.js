'use strict'

const { DB_TABLES, VALID_DAILY_LIMIT_CATEGORIES, MIN_ADMIN_LEVEL, MAX_ADMIN_LEVEL } = require('./shared')

const tableName = DB_TABLES.ADMIN_USERS

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
  },
  (_this, cb) => {
    _this.db.all(`SELECT name FROM sqlite_master WHERE type='table' AND name='${DB_TABLES.ADMIN_LEVEL_DAILY_LIMITS}' LIMIT 1`, [], (err, rows) => {
      if (err) return cb(err)
      if (rows?.length) return cb()

      _this.db.run(`
        CREATE TABLE IF NOT EXISTS ${DB_TABLES.ADMIN_LEVEL_DAILY_LIMITS} (
          level INTEGER NOT NULL CHECK (level BETWEEN ${MIN_ADMIN_LEVEL} AND ${MAX_ADMIN_LEVEL}),
          category TEXT NOT NULL CHECK (category IN (${VALID_DAILY_LIMIT_CATEGORIES.map(s => `'${s}'`).join(', ')})),
          alert INTEGER NOT NULL CHECK (alert >= 0),
          block INTEGER NOT NULL CHECK (block >= 0),

          PRIMARY KEY (level, category)
        )
      `, cb)
    })
  },
  (_this, cb) => {
    _this.db.all(`SELECT name FROM sqlite_master WHERE type='table' AND name='${DB_TABLES.ADMIN_USER_DAILY_LIMITS}' LIMIT 1`, [], (err, rows) => {
      if (err) return cb(err)
      if (rows?.length) return cb()
      _this.db.run(`
        CREATE TABLE IF NOT EXISTS ${DB_TABLES.ADMIN_USER_DAILY_LIMITS} (
          admin_id INTEGER,
          category TEXT NOT NULL CHECK (category IN (${VALID_DAILY_LIMIT_CATEGORIES.map(s => `'${s}'`).join(', ')})),
          alert INTEGER NOT NULL CHECK (alert >= 0),
          block INTEGER NOT NULL CHECK (block >= 0),

          PRIMARY KEY (admin_id, category),

          FOREIGN KEY(admin_id) REFERENCES ${DB_TABLES.ADMIN_USERS}(id)
        )
      `, cb)
    })
  }
]

module.exports = migrations
