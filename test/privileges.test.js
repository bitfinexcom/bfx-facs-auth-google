/* eslint-env mocha */

'use strict'

const assert = require('assert')
const { promisify } = require('util')
const { pick } = require('@bitfinex/lib-js-util-base')

const conf = require('./config/facs/auth-google.config')
const AuthGoogle = require('../')
const PrivilegeRepository = require('../src/privilege-repo')

const ctx = { root: './test' }
const caller = { ctx }
const authGoogle = new AuthGoogle(caller, { conf, db: ':memory:' }, ctx)

const testAdminEmail = 'testForms@admin.com'
const testPrivilege = 'sample-privilege:view'
const adminPayload = {
  email: testAdminEmail,
  password: 'test123',
  level: 0
}

describe('Admin Privileges', () => {
  beforeEach(async () => {
    await new Promise((resolve) => authGoogle.start(resolve))
  })

  afterEach(async () => {
    await new Promise((resolve) => authGoogle.stop(resolve))
  })

  it('should add privilege', async () => {
    const res = await authGoogle.addPrivilege(testPrivilege)
    assert.strictEqual(res.name, testPrivilege)

    await new Promise((resolve) => authGoogle.db.get('SELECT * FROM privileges WHERE name=?', [testPrivilege], (err, row) => {
      if (err) throw err
      assert.strictEqual(typeof row.id, 'number')
      assert.equal(row.name, testPrivilege)
      resolve()
    }))
  })

  it('should get all privileges', async () => {
    await authGoogle.addPrivilege(testPrivilege)
    const res = await authGoogle.getAllPrivileges()
    assert.strictEqual(res.length, 1)
    assert.deepStrictEqual(res, [{ id: 1, name: testPrivilege }])
  })

  it('should assign privilege to admin', async () => {
    await authGoogle.addPrivilege(testPrivilege)
    const savedAdmin = await authGoogle.addAdmin(adminPayload)

    const [privilege] = await authGoogle.getAllPrivileges()

    const res = await authGoogle.assignAdminPrivilege(adminPayload.email, privilege.id)
    assert.deepStrictEqual(res, {
      admin: savedAdmin.email,
      privilege: privilege.name
    })
  })

  it('should unassign privilege from admin', async () => {
    await authGoogle.addPrivilege(testPrivilege)
    const savedAdmin = await authGoogle.addAdmin(adminPayload)

    const [privilege] = await authGoogle.getAllPrivileges()

    const assigned = await authGoogle.assignAdminPrivilege(adminPayload.email, privilege.id)
    assert.deepStrictEqual(assigned, {
      admin: savedAdmin.email,
      privilege: privilege.name
    })

    const unassigned = await authGoogle.unAssignAdminPrivilege(adminPayload.email, privilege.id)
    assert.deepStrictEqual(unassigned, {
      admin: savedAdmin.email,
      privilege: privilege.name
    })
  })

  it('should throw error when assigning privilege if admin does not exist', async () => {
    await authGoogle.addPrivilege(testPrivilege)

    const [privilege] = await authGoogle.getAllPrivileges()

    try {
      await authGoogle.assignAdminPrivilege(adminPayload.email, privilege.id)
      throw new Error('SHOULD_NOT_REACH_THIS_POINT')
    } catch (err) {
      assert.strictEqual(err.message, 'INVALID_ADMIN')
    }
  })

  it('should throw error when assigning privilege if privilege does not exist', async () => {
    await authGoogle.addAdmin(adminPayload)

    try {
      await authGoogle.assignAdminPrivilege(adminPayload.email, 1)
      throw new Error('SHOULD_NOT_REACH_THIS_POINT')
    } catch (err) {
      assert.strictEqual(err.message, 'INVALID_PRIVILEGE_ID')
    }
  })

  it('should return an admin with their associated privileges', async () => {
    await authGoogle.addPrivilege(testPrivilege)
    await authGoogle.addAdmin(adminPayload)

    const [privilege] = await authGoogle.getAllPrivileges()

    await authGoogle.assignAdminPrivilege(adminPayload.email, privilege.id)

    const res = await authGoogle.getAdminWithPrivileges(adminPayload.email)
    assert.deepStrictEqual(pick(res, ['email', 'level', 'active', 'privileges']), {
      email: adminPayload.email,
      level: adminPayload.level,
      active: 1,
      privileges: [{ id: 1, name: testPrivilege }]
    })
  })

  it('should check if an admin has a required privilege', async () => {
    await authGoogle.addPrivilege(testPrivilege)
    await authGoogle.addAdmin(adminPayload)

    const [privilege] = await authGoogle.getAllPrivileges()

    await authGoogle.assignAdminPrivilege(adminPayload.email, privilege.id)

    const hasPrivilege = await authGoogle.checkAdminHasRequiredPrivilege(adminPayload.email, privilege.name)
    assert.deepStrictEqual(hasPrivilege, true)

    const missingPrivilege = await authGoogle.checkAdminHasRequiredPrivilege(adminPayload.email, 'INVALID:PRIVILEGE')
    assert.deepStrictEqual(missingPrivilege, false)
  })

  it('deleting a privilege should cascade and unassign the associated assigned privileges', async () => {
    await authGoogle.addPrivilege(testPrivilege)
    await authGoogle.addAdmin(adminPayload)

    const [privilege] = await authGoogle.getAllPrivileges()

    await authGoogle.assignAdminPrivilege(adminPayload.email, privilege.id)

    const hasPrivilege = await authGoogle.checkAdminHasRequiredPrivilege(adminPayload.email, privilege.name)
    assert.deepStrictEqual(hasPrivilege, true)

    const runSqlFn = promisify(authGoogle.db.run.bind(authGoogle.db))
    await runSqlFn(`DELETE FROM ${PrivilegeRepository.tableName} WHERE id=?`, [privilege.id])

    {
      const hasPrivilege = await authGoogle.checkAdminHasRequiredPrivilege(adminPayload.email, privilege.name)
      assert.deepStrictEqual(hasPrivilege, false)
    }
  })
})
