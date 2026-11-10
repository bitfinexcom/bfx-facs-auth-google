'use strict'

const assert = require('assert')
const fs = require('fs')
const path = require('path')
const brittleTest = require('brittle')

const conf = require('./config/facs/auth-google.config')

const AuthGoogle = require('../')
const { omit } = require('@bitfinex/lib-js-util-base')

const dbPath = path.join(__dirname, './db/')
const ctx = { root: './test' }

const mongoFac = {
  db: {
    collection: () => ({
      insertOne: (query, cb) => cb(null, query)
    })
  }
}

const caller = { ctx, dbMongo_m0: mongoFac }
const authGoogle = new AuthGoogle(caller, { conf }, ctx)

const cleanup = () => {
  if (fs.existsSync(dbPath)) {
    fs.rmSync(dbPath, { recursive: true, force: true })
  }
}

const setup = async (t) => {
  cleanup()
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

const testForms = ['passport', 'bank_statement', 'merchant']
const testAdminEmail = 'testForms@admin.com'
const adminPayload = {
  email: testAdminEmail,
  password: 'test123',
  level: 0
}
const testAdminWithForms = {
  ...adminPayload,
  forms: testForms
}

test('should add admin and stringify forms field', async (t) => {
  const admin = await authGoogle.addAdmin(testAdminWithForms)
  assert.strictEqual(typeof admin.id, 'number', 'admin id should be defined')

  await new Promise((resolve) => authGoogle.db.get('SELECT * FROM admin_users WHERE email=?', [testAdminEmail], (err, row) => {
    if (err) throw err
    assert.equal(row.forms, JSON.stringify(testForms))
    resolve()
  }))
})

test('should return admin and with parsed form fields', async (t) => {
  await authGoogle.addAdmin(testAdminWithForms)

  const res = await authGoogle.getAdmin(testAdminEmail)

  assert.deepEqual(res.forms, testForms)
})

test('loginAdmin should pass error AUTH_FAC_ACCOUNT_IS_NOT_VALID to callback when internal validation of google auth credentials throws an exception', { timeout: 5000 }, async (t) => {
  let errMsg = null
  const args = { google: { credential: 'invalid credential' } }
  const cb = (e) => {
    errMsg = e.message
  }
  await authGoogle.loginAdmin(args, cb)
  assert.strictEqual(errMsg, 'AUTH_FAC_ACCOUNT_IS_NOT_VALID')
})

test('updateAdmin should validate passwordResetToken', async (t) => {
  await authGoogle.addAdmin(adminPayload)
  try {
    await authGoogle.updateAdmin(adminPayload.email, { passwordResetToken: 40 })
    throw new Error('SHOULD_NOT_REACH_THIS_POINT')
  } catch (err) {
    assert.strictEqual(err.message, 'passwordResetToken should be a string')
  }

  try {
    await authGoogle.updateAdmin(adminPayload.email, { passwordResetToken: false })
    throw new Error('SHOULD_NOT_REACH_THIS_POINT')
  } catch (err) {
    assert.strictEqual(err.message, 'passwordResetToken should be a string')
  }

  const update = await authGoogle.updateAdmin(adminPayload.email, { passwordResetToken: 'sample_token' })
  assert.strictEqual(update.passwordResetToken, 'sample_token')
})

test('updateAdmin should validate passwordResetSentAt', async (t) => {
  await authGoogle.addAdmin(adminPayload)
  try {
    await authGoogle.updateAdmin(adminPayload.email, { passwordResetSentAt: 'invalid date' })
    throw new Error('SHOULD_NOT_REACH_THIS_POINT')
  } catch (err) {
    assert.strictEqual(err.message, 'passwordResetSentAt should be a valid date')
  }

  const now = new Date().toISOString()
  const update = await authGoogle.updateAdmin(adminPayload.email, { passwordResetSentAt: now })
  assert.strictEqual(update.passwordResetSentAt, now)
})

const hasJustBeenCreated = payload => assert.ok(Date.now() - new Date(payload.timestamp + 'Z').getTime() < 1000)

const getAdminAssertions = (getAdminResult, expectedActive = true) => {
  assert.equal(getAdminResult.email, adminPayload.email)
  assert.equal(getAdminResult.level, adminPayload.level)
  assert.equal(getAdminResult.active, expectedActive)
  hasJustBeenCreated(getAdminResult)
}

test('getAdmin should get active admin', async (t) => {
  await authGoogle.addAdmin(adminPayload)

  const getAdminResult = await authGoogle.getAdmin(adminPayload.email)

  getAdminAssertions(getAdminResult)
})

test('getAdmin should not get inactive admin', async (t) => {
  await authGoogle.addAdmin(adminPayload)
  await authGoogle.updateAdmin(adminPayload.email, { active: false })

  const getAdminResult = await authGoogle.getAdmin(adminPayload.email)

  assert.equal(getAdminResult, undefined)
})

test('getAdmin should get inactive admin', async (t) => {
  await authGoogle.addAdmin(adminPayload)
  await authGoogle.updateAdmin(adminPayload.email, { active: false })

  const getAdminResult = await authGoogle.getAdmin(adminPayload.email, false)

  getAdminAssertions(getAdminResult, false)
})

test('getAdmin should get admin using uppercased email', async (t) => {
  await authGoogle.addAdmin(adminPayload)

  const getAdminResult = await authGoogle.getAdmin(adminPayload.email.toUpperCase())

  getAdminAssertions(getAdminResult)
})

test('getAdmin should get admin using id', async (t) => {
  const adminCreationResult = await authGoogle.addAdmin(adminPayload)

  const getAdminResult = await authGoogle.getAdmin(adminCreationResult.id, true, true)

  getAdminAssertions(getAdminResult)
})

test('fetchMotivationsPrivilege permission should add admin successfully with fetchMotivationsPrivilege', async (t) => {
  await authGoogle.addAdmin({
    ...testAdminWithForms,
    fetchMotivationsPrivilege: true
  })

  const res = await authGoogle.getAdmin(testAdminEmail)

  assert.strictEqual(res.fetchMotivationsPrivilege, 1)
})

test('fetchMotivationsPrivilege permission should throw error when adding admin with fetchMotivationsPrivilege not being boolean', async (t) => {
  try {
    await authGoogle.addAdmin({
      ...testAdminWithForms,
      fetchMotivationsPrivilege: 'not boolean'
    })
    throw new Error('SHOULD_NOT_REACH_HERE')
  } catch (e) {
    assert.ok(e instanceof assert.AssertionError)
    assert.strictEqual(e.message, 'fetchMotivationsPrivilege should be a boolean')
  }
})

test('fetchMotivationsPrivilege permission should edit admin successfully with fetchMotivationsPrivilege', async (t) => {
  await authGoogle.addAdmin(testAdminWithForms)
  const adminBeforeUpdate = await authGoogle.getAdmin(testAdminEmail)
  assert.ok(!adminBeforeUpdate.fetchMotivationsPrivilege)

  await authGoogle.updateAdmin(testAdminEmail, {
    ...omit(testAdminWithForms, ['email', 'password', 'forms']),
    fetchMotivationsPrivilege: true
  })
  const adminAfterUpdate = await authGoogle.getAdmin(testAdminEmail)
  assert.strictEqual(adminAfterUpdate.fetchMotivationsPrivilege, 1)
})

test('fetchMotivationsPrivilege permission should throw error when editing admin with fetchMotivationsPrivilege not being boolean', async (t) => {
  await authGoogle.addAdmin(testAdminWithForms)
  const adminBeforeUpdate = await authGoogle.getAdmin(testAdminEmail)
  assert.ok(!adminBeforeUpdate.fetchMotivationsPrivilege)

  try {
    await authGoogle.updateAdmin(testAdminEmail, {
      ...omit(testAdminWithForms, ['email', 'password', 'forms']),
      fetchMotivationsPrivilege: 'not boolean'
    })
    throw new Error('SHOULD_NOT_REACH_HERE')
  } catch (e) {
    assert.ok(e instanceof assert.AssertionError)
    assert.strictEqual(e.message, 'fetchMotivationsPrivilege should be a boolean')
  }
})

test('fetchMotivationsPrivilege permission should return true when admin has fetch motivations privilege', async (t) => {
  await authGoogle.addAdmin({
    ...testAdminWithForms,
    level: 1,
    fetchMotivationsPrivilege: true
  })

  const res = await authGoogle.checkAdmHasFetchMotivationsPrivilege(testAdminEmail)

  assert.ok(res)
})

test('fetchMotivationsPrivilege permission should return false when admin does not have fetch motivations privilege', async (t) => {
  await authGoogle.addAdmin({
    ...testAdminWithForms,
    level: 1,
    fetchMotivationsPrivilege: false
  })

  const res = await authGoogle.checkAdmHasFetchMotivationsPrivilege(testAdminEmail)

  assert.ok(!res)
})

const ips = ['192.168.1.1', '10.0.0.5']
const adminWithIps = {
  email: testAdminEmail,
  password: 'test123',
  level: 0,
  whitelistedIps: ips
}

test('whitelistedIps field should add admin and stringify whitelistedIps in the DB', async (t) => {
  await authGoogle.addAdmin(adminWithIps)

  await new Promise((resolve) => authGoogle.db.get('SELECT * FROM admin_users WHERE email=?', [testAdminEmail], (err, row) => {
    if (err) throw err
    assert.equal(row.whitelistedIps, JSON.stringify(ips))
    resolve()
  }))
})

test('whitelistedIps field should return whitelistedIps as a parsed array from getAdmin', async (t) => {
  await authGoogle.addAdmin(adminWithIps)

  const res = await authGoogle.getAdmin(testAdminEmail)

  assert.deepEqual(res.whitelistedIps, ips)
})

test('whitelistedIps field should return undefined whitelistedIps when not set on admin', async (t) => {
  await authGoogle.addAdmin({ email: testAdminEmail, password: 'test123', level: 0 })

  const res = await authGoogle.getAdmin(testAdminEmail)

  assert.equal(res.whitelistedIps, undefined)
})

test('whitelistedIps field should throw when adding admin with whitelistedIps not being an array', async (t) => {
  try {
    await authGoogle.addAdmin({ ...adminWithIps, whitelistedIps: '192.168.1.1' })
    throw new Error('SHOULD_NOT_REACH_HERE')
  } catch (e) {
    assert.ok(e instanceof assert.AssertionError)
    assert.strictEqual(e.message, 'whitelistedIps should be an array')
  }
})

test('whitelistedIps field should update whitelistedIps and return the new list from getAdmin', async (t) => {
  await authGoogle.addAdmin(adminWithIps)
  const adminBeforeUpdate = await authGoogle.getAdmin(testAdminEmail)
  assert.deepEqual(adminBeforeUpdate.whitelistedIps, ips)

  const updatedIps = ['203.0.113.10']
  await authGoogle.updateAdmin(testAdminEmail, { whitelistedIps: updatedIps })

  const adminAfterUpdate = await authGoogle.getAdmin(testAdminEmail)
  assert.deepEqual(adminAfterUpdate.whitelistedIps, updatedIps)
})

test('updateAdminPassword should change the user password if the old password is valid', async (t) => {
  await authGoogle.addAdmin({ ...adminPayload })

  let resp
  const cb = (_, res) => {
    resp = res
  }
  await authGoogle.loginAdmin({
    user: {
      username: adminPayload.email,
      password: adminPayload.password
    }
  }, cb)
  assert.strictEqual(resp.username, adminPayload.email)
  assert.strictEqual(typeof resp.token, 'string')
  assert.strictEqual(typeof resp.password, 'undefined')
  assert.strictEqual(typeof resp.id, 'number')
  assert.ok(resp.active)
  assert.ok(Array.isArray(resp.privileges))

  const newPassword = 'newPassword'
  assert.ok(adminPayload.password !== newPassword)
  const successful = await authGoogle.updateAdminPassword(adminPayload.email, newPassword, adminPayload.password)
  assert.strictEqual(successful, true)

  await authGoogle.loginAdmin({
    user: {
      username: adminPayload.email,
      password: newPassword
    }
  }, cb)
  assert.strictEqual(resp.username, adminPayload.email)
  assert.strictEqual(typeof resp.token, 'string')
  assert.strictEqual(typeof resp.password, 'undefined')
  assert.strictEqual(typeof resp.id, 'number')
  assert.ok(resp.active)
  assert.ok(Array.isArray(resp.privileges))
})

test('updateAdminPassword should validate the params', async (t) => {
  try {
    await authGoogle.updateAdminPassword(1)
    throw new Error('SHOULD_NOT_REACH_THIS_POINT')
  } catch (err) {
    assert.strictEqual(err.message, 'Email is required')
  }

  try {
    await authGoogle.updateAdminPassword(adminPayload.email)
    throw new Error('SHOULD_NOT_REACH_THIS_POINT')
  } catch (err) {
    assert.strictEqual(err.message, 'New Password is required')
  }

  try {
    await authGoogle.updateAdminPassword(adminPayload.email, 'newPassword')
    throw new Error('SHOULD_NOT_REACH_THIS_POINT')
  } catch (err) {
    assert.strictEqual(err.message, 'Old Password is required')
  }

  try {
    await authGoogle.updateAdminPassword(adminPayload.email, 'newPassword', adminPayload.password)
    throw new Error('SHOULD_NOT_REACH_THIS_POINT')
  } catch (err) {
    assert.strictEqual(err.message, 'ADMIN_ACCOUNT_DOES_NOT_EXIST_OR_IS_NOT_ACTIVE')
  }

  await authGoogle.addAdmin({ ...adminPayload })

  try {
    await authGoogle.updateAdminPassword(adminPayload.email, 'newPassword', 'wrongPassword')
    throw new Error('SHOULD_NOT_REACH_THIS_POINT')
  } catch (err) {
    assert.strictEqual(err.message, 'INVALID_PASSWORD')
  }
})

test('resetPassword should reset the user password if the token is valid', async (t) => {
  await authGoogle.addAdmin({ ...adminPayload })

  let resp
  const cb = (_, res) => {
    resp = res
  }
  await authGoogle.loginAdmin({
    user: {
      username: adminPayload.email,
      password: adminPayload.password
    }
  }, cb)
  assert.strictEqual(resp.username, adminPayload.email)
  assert.strictEqual(typeof resp.token, 'string')
  assert.strictEqual(typeof resp.password, 'undefined')
  assert.strictEqual(typeof resp.id, 'number')
  assert.ok(resp.active)
  assert.ok(Array.isArray(resp.privileges))

  const passwordResetToken = 'sample_token'
  const update = await authGoogle.updateAdmin(adminPayload.email, { passwordResetToken, passwordResetSentAt: new Date().toISOString() })
  assert.strictEqual(update.passwordResetToken, 'sample_token')

  const newPassword = 'newPassword'
  assert.ok(adminPayload.password !== newPassword)
  const successful = await authGoogle.resetAdminPassword(adminPayload.email, newPassword, passwordResetToken)
  assert.strictEqual(successful, true)

  await authGoogle.loginAdmin({
    user: {
      username: adminPayload.email,
      password: newPassword
    }
  }, cb)
  assert.strictEqual(resp.username, adminPayload.email)
  assert.strictEqual(typeof resp.token, 'string')
  assert.strictEqual(typeof resp.password, 'undefined')
  assert.strictEqual(typeof resp.id, 'number')
  assert.ok(resp.active)
  assert.ok(Array.isArray(resp.privileges))
})

test('resetPassword should validate the params', async (t) => {
  try {
    await authGoogle.resetAdminPassword(1)
    throw new Error('SHOULD_NOT_REACH_THIS_POINT')
  } catch (err) {
    assert.strictEqual(err.message, 'Email is required')
  }

  try {
    await authGoogle.resetAdminPassword(adminPayload.email)
    throw new Error('SHOULD_NOT_REACH_THIS_POINT')
  } catch (err) {
    assert.strictEqual(err.message, 'New Password is required')
  }

  const passwordResetToken = 'sample_token'
  try {
    await authGoogle.resetAdminPassword(adminPayload.email, 'newPassword', passwordResetToken)
    throw new Error('SHOULD_NOT_REACH_THIS_POINT')
  } catch (err) {
    assert.strictEqual(err.message, 'ADMIN_ACCOUNT_DOES_NOT_EXIST_OR_IS_NOT_ACTIVE')
  }

  await authGoogle.addAdmin({ ...adminPayload })

  try {
    await authGoogle.resetAdminPassword(adminPayload.email, 'newPassword', passwordResetToken)
    throw new Error('SHOULD_NOT_REACH_THIS_POINT')
  } catch (err) {
    assert.strictEqual(err.message, 'INVALID_passwordResetToken')
  }

  const update = await authGoogle.updateAdmin(adminPayload.email, {
    passwordResetToken,
    passwordResetSentAt: new Date(2020, 1, 1).toISOString() // expired date
  })
  assert.strictEqual(update.passwordResetToken, 'sample_token')

  try {
    await authGoogle.resetAdminPassword(adminPayload.email, 'newPassword', passwordResetToken)
    throw new Error('SHOULD_NOT_REACH_THIS_POINT')
  } catch (err) {
    assert.strictEqual(err.message, 'RESET_LINK_EXPIRED')
  }
})
