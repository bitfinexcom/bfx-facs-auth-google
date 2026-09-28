'use strict'

const assert = require('assert')
const BaseRepository = require('./repository')

class PrivilegeRepository extends BaseRepository {
  static tableName = 'privileges'

  /**
   *
   * @param {import('sqlite3').Database} db
   * @param {{useDb: boolean}} conf
   */
  constructor (db, conf) {
    super(db, PrivilegeRepository.tableName, conf)
  }

  /**
   *
   * @param {object} param0
   * @param {string} param0.name
   * @returns {Promise<{name: string}>}
   */
  add ({ name }) {
    const trimmedName = name?.trim()
    assert.ok(trimmedName && typeof trimmedName === 'string', 'Name is a required string')
    return super.add({ name: trimmedName })
  }
}

module.exports = PrivilegeRepository
