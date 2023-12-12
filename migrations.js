'use strict'

const tableName = 'admin_users'

const migrations = [
  (_this, cb) => {
    _this.db.run(`
      ALTER TABLE ${tableName}
      ADD manageAdminsPrivilege TINYINTEGER
    `, cb)
  },
  (_this, cb) => {
    _this.db.run(`
      ALTER TABLE ${tableName}
      ADD forms TEXT
    `, cb)
  }
]

module.exports = migrations
