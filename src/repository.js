'use strict'

const assert = require('assert')
const { isBoolean } = require('@bitfinex/lib-js-util-base')

class BaseRepository {
  /**
   *
   * @param {import('better-sqlite3').Database} db
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
   * @returns {data & {id: number}}
   */
  add (data) {
    const keys = Object.keys(data)
    const params = Object.values(data).map(value => isBoolean(value) ? Number(value) : value)
    const result = this.db.prepare(`INSERT INTO ${this.tableName} (${keys.join(', ')}) VALUES (${Array(keys.length).fill('?').join(', ')})`).run(...params)
    return { ...data, id: result.lastInsertRowid }
  }

  /**
   *
   * @returns {Array}
   */
  findAll () {
    return this.db.prepare(`SELECT * FROM ${this.tableName}`).all()
  }

  /**
   * @param {number} id
   * @return {object}
   */
  findById (id) {
    assert.ok(this.conf.useDB, 'Cannot use repository pattern if DB is not available')
    return this.db.prepare(`SELECT * FROM ${this.tableName} WHERE id=?`).get(id)
  }
}

module.exports = BaseRepository
