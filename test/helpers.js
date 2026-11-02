'use strict'

const clearSqliteDb = (sqliteDb) => {
  const tables = sqliteDb.prepare(`SELECT name
                               FROM sqlite_master
                               WHERE type = 'table';`).all()
  for (const { name } of tables) {
    sqliteDb.prepare(`DELETE
                  FROM ${name}
                  WHERE true`).run()
  }
}

module.exports = { clearSqliteDb }
