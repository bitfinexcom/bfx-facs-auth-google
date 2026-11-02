'use strict'

const { FORMS_FIELD } = require('./src/admin-user-repo')
const tableName = 'admin_users'
const privilegesTable = 'privileges'
const adminPrivilegeTable = 'admin_privileges'

/**
 *
 * @param {import('better-sqlite3').Database} db
 */
const betterSqliteMigration = (db) => {
  db.transaction(() => {
    db.exec(`CREATE TABLE IF NOT EXISTS ${tableName}
             (
                 id                                 INTEGER PRIMARY KEY AUTOINCREMENT,
                 email                              TEXT UNIQUE NOT NULL,
                 password                           TEXT,
                 level                              INTEGER     NOT NULL,
                 active                TINYINTEGER DEFAULT 1,
                 readOnly              TINYINTEGER,
                 blockPrivilege        TINYINTEGER,
                 analyticsPrivilege    TINYINTEGER,
                 manageAdminsPrivilege TINYINTEGER,
                 casesPrivilege        TINYINTEGER,
                 passwordResetToken    TEXT,
                 passwordResetSentAt   DATETIME,
                 company               TEXT,
                 timestamp             DATETIME    DEFAULT CURRENT_TIMESTAMP,
                 ${FORMS_FIELD}        TEXT,
                 whitelistedIps        TEXT
             )`)
    db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS uidx_email ON ${tableName} (email ASC)`)
    const rows = db.prepare(`PRAGMA table_info(${tableName})`).all()
    if (!rows.some(row => row.name === 'manageAdminsPrivilege')) {
      db.prepare(`ALTER TABLE ${tableName}
            ADD manageAdminsPrivilege TINYINTEGER`).run()
    }
    if (!rows.some(row => row.name === 'forms')) {
      db.exec(`ALTER TABLE ${tableName}
            ADD forms TEXT`)
    }
    if (!rows.some(row => row.name === 'passwordResetSentAt')) {
      db.exec(`ALTER TABLE ${tableName}
            ADD passwordResetSentAt DATETIME`)
    }
    if (!rows.some(row => row.name === 'passwordResetToken')) {
      db.exec(`ALTER TABLE ${tableName}
            ADD passwordResetToken TEXT`)
    }
    if (!rows.some(row => row.name === 'fetchMotivationsPrivilege')) {
      db.exec(`ALTER TABLE ${tableName}
            ADD fetchMotivationsPrivilege BOOLEAN`)
    }
    if (!rows.some(row => row.name === 'casesPrivilege')) {
      db.exec(`ALTER TABLE ${tableName}
            ADD casesPrivilege TINYINTEGER`)
    }
    if (!rows.some(row => row.name === 'whitelistedIps')) {
      db.exec(`ALTER TABLE ${tableName}
            ADD whitelistedIps TEXT`)
    }
    db.exec('PRAGMA foreign_keys = ON;')
    db.exec(`CREATE TABLE IF NOT EXISTS ${privilegesTable}
               (
                   id   INTEGER PRIMARY KEY AUTOINCREMENT,
                   name TEXT NOT NULL UNIQUE
               );`)
    db.exec(`
          CREATE TABLE IF NOT EXISTS ${adminPrivilegeTable}
          (
              admin_id     INTEGER NOT NULL,
              privilege_id INTEGER NOT NULL,

              PRIMARY KEY (admin_id, privilege_id),

              FOREIGN KEY (admin_id) REFERENCES admin_users (id) ON DELETE CASCADE,
              FOREIGN KEY (privilege_id) REFERENCES privileges (id) ON DELETE CASCADE
          );`)
  })()
}

module.exports = betterSqliteMigration
