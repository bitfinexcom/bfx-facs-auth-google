'use strict'

const assert = require('assert')

class BaseRepository {
  /**
   *
   * @param {import('sqlite3').Database} db
   * @param {string} tableName
   * @param {Record<string, any>} conf
   */
  constructor (db, tableName, conf) {
    this.db = db
    this.tableName = tableName
    this.conf = conf

    assert.ok(this.conf.useDB, 'Cannot use repository pattern if DB is not available')
  }

  /**
   *
   * @param {object} data
   * @returns {Promise<data & {id: number}>}
   */
  add (data) {
    return new Promise((resolve, reject) => {
      const keys = Object.keys(data)

      this.db.run(
        `INSERT INTO ${this.tableName} (${keys.join(', ')}) VALUES (${Array(keys.length).fill('?').join(', ')})`,
        Object.values(data),
        function (err) {
          if (err) return reject(err)

          return resolve({ ...data, id: this.lastID })
        }
      )
    })
  }

  /**
   *
   * @returns {Promise<Array>}
   */
  findAll () {
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT * FROM ${this.tableName}`,
        [],
        function (err, rows) {
          if (err) return reject(err)

          return resolve(rows)
        }
      )
    })
  }

  /**
   *
   * @param {number} id
   * @returns
   */
  findById (id) {
    assert.ok(this.conf.useDB, 'Cannot use repository pattern if DB is not available')

    return new Promise((resolve, reject) => {
      this.db.get(
        `SELECT * FROM ${this.tableName} WHERE id=?`,
        [id],
        function (err, row) {
          if (err) return reject(err)

          return resolve(row)
        }
      )
    })
  }
}

module.exports = BaseRepository
