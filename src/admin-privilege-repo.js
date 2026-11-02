'use strict'

const assert = require('assert')
const BaseRepository = require('./repository')
const PrivilegeRepository = require('./privilege-repo')

class AdminPrivilegeRepository extends BaseRepository {
  static tableName = 'admin_privileges'

  /**
   *
   * @param {import('better-sqlite3').Database} db
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
   * @returns {object}
   */
  findAdminPrivilege (adminId, privilege) {
    const query = `SELECT ap.admin_id, ap.privilege_id, p.name as privilege_name
        FROM ${this.tableName} ap
        JOIN ${PrivilegeRepository.tableName} p ON p.id = ap.privilege_id
        WHERE ap.admin_id=? AND p.name=?
        LIMIT 1;`
    return this.db.prepare(query).get(adminId, privilege)
  }

  getAdminPrivileges (adminId) {
    const query = `
        SELECT p.id, p.name
        FROM ${this.tableName} ap
        JOIN ${PrivilegeRepository.tableName} p ON p.id = ap.privilege_id
        WHERE ap.admin_id = ?;
      `
    return this.db.prepare(query).all(adminId)
  }

  remove (adminId, privilegeId) {
    const query = `
        DELETE FROM ${this.tableName}
        WHERE admin_id = ?
        AND privilege_id = ?;
      `
    return this.db.prepare(query).run(adminId, privilegeId)
  }
}

module.exports = AdminPrivilegeRepository
