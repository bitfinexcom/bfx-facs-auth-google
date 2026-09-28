'use strict'

const assert = require('assert')
const BaseRepository = require('./repository')
const PrivilegeRepository = require('./privilege-repo')

class AdminPrivilegeRepository extends BaseRepository {
  static tableName = 'admin_privileges'

  /**
   *
   * @param {import('sqlite3').Database} db
   * @param {{useDb: boolean}} conf
   */
  constructor (db, conf) {
    super(db, AdminPrivilegeRepository.tableName, conf)
  }

  /**
   *
   * @param {object} param0
   * @param {number} param0.adminId
   * @param {number} param0.privilegeId
   * @returns {Promise<{admin_id, privilege_id}>}
   */
  add ({ adminId, privilegeId }) {
    assert.ok(adminId && typeof adminId === 'number', 'Admin ID is a required Integer')
    assert.ok(privilegeId && typeof privilegeId === 'number', 'Privilege ID is a required Integer')
    return super.add({ admin_id: adminId, privilege_id: privilegeId })
  }

  /**
   *
   * @param {number} adminId
   * @param {string} privilege
   * @returns {Promise<object>}
   */
  findAdminPrivilege (adminId, privilege) {
    return new Promise((resolve, reject) => {
      this.db.get(
        `SELECT ap.admin_id, ap.privilege_id, p.name as privilege_name
        FROM ${this.tableName} ap
        JOIN ${PrivilegeRepository.tableName} p ON p.id = ap.privilege_id
        WHERE ap.admin_id=? AND p.name=?
        LIMIT 1;`,
        [adminId, privilege],
        function (err, row) {
          if (err) return reject(err)

          return resolve(row)
        }
      )
    })
  }

  getAdminPrivileges (adminId) {
    return new Promise((resolve, reject) => {
      const query = `
        SELECT p.id, p.name
        FROM ${this.tableName} ap
        JOIN ${PrivilegeRepository.tableName} p ON p.id = ap.privilege_id
        WHERE ap.admin_id = ?;
      `
      this.db.all(query, [adminId], function (err, rows) {
        if (err) return reject(err)
        return resolve(rows)
      })
    })
  }

  remove (adminId, privilegeId) {
    return new Promise((resolve, reject) => {
      const query = `
        DELETE FROM ${this.tableName}
        WHERE admin_id = ?
        AND privilege_id = ?;
      `
      this.db.run(query, [adminId, privilegeId], function (err, rows) {
        if (err) return reject(err)
        return resolve(rows)
      })
    })
  }
}

module.exports = AdminPrivilegeRepository
