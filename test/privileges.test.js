'use strict'

const { promisify } = require('util')
const { pick } = require('@bitfinex/lib-js-util-base')
const brittleTest = require('brittle')

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

const setup = async (t) => {
  await new Promise((resolve) => authGoogle.start(resolve))
  t.teardown(async () => {
    await new Promise((resolve) => authGoogle.stop(resolve))
  })
}

const test = (name, options, fn) => {
  if (typeof options === 'function') {
    fn = options
    options = undefined
  }
  return brittleTest(name, options, async (t) => {
    await setup(t)
    return fn(t)
  })
}

test('should add privilege', async (t) => {
  const res = await authGoogle.addPrivilege(testPrivilege)
  t.is(res.name, testPrivilege)

  await new Promise((resolve) => authGoogle.db.get('SELECT * FROM privileges WHERE name=?', [testPrivilege], (err, row) => {
    if (err) throw err
    t.is(typeof row.id, 'number')
    t.is(row.name, testPrivilege)
    resolve()
  }))
})

test('should get all privileges', async (t) => {
  await authGoogle.addPrivilege(testPrivilege)
  const res = await authGoogle.getAllPrivileges()
  t.is(res.length, 1)
  t.alike(res, [{ id: 1, name: testPrivilege }])
})

test('should assign privilege to admin', async (t) => {
  await authGoogle.addPrivilege(testPrivilege)
  const savedAdmin = await authGoogle.addAdmin(adminPayload)

  const [privilege] = await authGoogle.getAllPrivileges()

  const res = await authGoogle.assignAdminPrivilege(adminPayload.email, privilege.id)
  t.alike(res, {
    admin: savedAdmin.email,
    privilege: privilege.name
  })
})

test('should unassign privilege from admin', async (t) => {
  await authGoogle.addPrivilege(testPrivilege)
  const savedAdmin = await authGoogle.addAdmin(adminPayload)

  const [privilege] = await authGoogle.getAllPrivileges()

  const assigned = await authGoogle.assignAdminPrivilege(adminPayload.email, privilege.id)
  t.alike(assigned, {
    admin: savedAdmin.email,
    privilege: privilege.name
  })

  const unassigned = await authGoogle.unAssignAdminPrivilege(adminPayload.email, privilege.id)
  t.alike(unassigned, {
    admin: savedAdmin.email,
    privilege: privilege.name
  })
})

test('should throw error when assigning privilege if admin does not exist', async (t) => {
  await authGoogle.addPrivilege(testPrivilege)

  const [privilege] = await authGoogle.getAllPrivileges()

  try {
    await authGoogle.assignAdminPrivilege(adminPayload.email, privilege.id)
    throw new Error('SHOULD_NOT_REACH_THIS_POINT')
  } catch (err) {
    t.is(err.message, 'INVALID_ADMIN')
  }
})

test('should throw error when assigning privilege if privilege does not exist', async (t) => {
  await authGoogle.addAdmin(adminPayload)

  try {
    await authGoogle.assignAdminPrivilege(adminPayload.email, 1)
    throw new Error('SHOULD_NOT_REACH_THIS_POINT')
  } catch (err) {
    t.is(err.message, 'INVALID_PRIVILEGE_ID')
  }
})

test('should return an admin with their associated privileges', async (t) => {
  await authGoogle.addPrivilege(testPrivilege)
  await authGoogle.addAdmin(adminPayload)

  const [privilege] = await authGoogle.getAllPrivileges()

  await authGoogle.assignAdminPrivilege(adminPayload.email, privilege.id)

  const res = await authGoogle.getAdminWithPrivileges(adminPayload.email)
  t.alike({ ...pick(res, ['email', 'level', 'active', 'privileges']) }, {
    email: adminPayload.email,
    level: adminPayload.level,
    active: 1,
    privileges: [{ id: 1, name: testPrivilege }]
  })
})

test('should check if an admin has a required privilege', async (t) => {
  await authGoogle.addPrivilege(testPrivilege)
  await authGoogle.addAdmin(adminPayload)

  const [privilege] = await authGoogle.getAllPrivileges()

  await authGoogle.assignAdminPrivilege(adminPayload.email, privilege.id)

  const hasPrivilege = await authGoogle.checkAdminHasRequiredPrivilege(adminPayload.email, privilege.name)
  t.alike(hasPrivilege, true)

  const missingPrivilege = await authGoogle.checkAdminHasRequiredPrivilege(adminPayload.email, 'INVALID:PRIVILEGE')
  t.alike(missingPrivilege, false)
})

test('deleting a privilege should cascade and unassign the associated assigned privileges', async (t) => {
  await authGoogle.addPrivilege(testPrivilege)
  await authGoogle.addAdmin(adminPayload)

  const [privilege] = await authGoogle.getAllPrivileges()

  await authGoogle.assignAdminPrivilege(adminPayload.email, privilege.id)

  const hasPrivilege = await authGoogle.checkAdminHasRequiredPrivilege(adminPayload.email, privilege.name)
  t.alike(hasPrivilege, true)

  const runSqlFn = promisify(authGoogle.db.run.bind(authGoogle.db))
  await runSqlFn(`DELETE FROM ${PrivilegeRepository.tableName} WHERE id=?`, [privilege.id])

  {
    const hasPrivilege = await authGoogle.checkAdminHasRequiredPrivilege(adminPayload.email, privilege.name)
    t.alike(hasPrivilege, false)
  }
})
