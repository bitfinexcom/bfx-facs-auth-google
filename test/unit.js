/* eslint-env mocha */

'use strict'

const assert = require('assert')
const fs = require('fs')
const path = require('path')

const conf = require('./config/facs/auth-google.config')

const AuthGoogle = require('../')
const { omit } = require('@bitfinex/lib-js-util-base')

const dbPath = path.join(__dirname, './db/')
const ctx = { root: './test' }
const caller = { ctx }
const authGoogle = new AuthGoogle(caller, { conf }, ctx)

const cleanup = () => {
  if (fs.existsSync(dbPath)) {
    fs.rmSync(dbPath, { recursive: true, force: true })
  }
}

const testForms = ['passport', 'bank_statement', 'merchant']
const testAdminEmail = 'testForms@admin.com'
const testAdminWithForms = {
  email: testAdminEmail,
  password: 'test123',
  level: 0,
  forms: testForms
}

describe('forms field', () => {
  beforeEach(async () => {
    cleanup()
    await new Promise((resolve) => authGoogle.start(resolve))
  })

  afterEach(async () => {
    await new Promise((resolve) => authGoogle.stop(resolve))
  })

  it('should add admin and stringify forms field', async () => {
    await authGoogle.addAdmin(testAdminWithForms)

    await new Promise((resolve) => authGoogle.db.get('SELECT * FROM admin_users WHERE email=?', [testAdminEmail], (err, row) => {
      if (err) throw err
      assert.equal(row.forms, JSON.stringify(testForms))
      resolve()
    }))
  })

  it('should return admin and with parsed form fields', async () => {
    await authGoogle.addAdmin(testAdminWithForms)

    const res = await authGoogle.getAdmin(testAdminEmail)

    assert.deepEqual(res.forms, testForms)
  })

  describe('getAdmin', () => {
    const adminPayload = {
      email: testAdminEmail,
      password: 'test123',
      level: 0
    }

    const hasJustBeenCreated = payload => assert.ok(Date.now() - new Date(payload.timestamp) < 1000)

    const assertions = (getAdminResult, expectedActive = true) => {
      assert.equal(getAdminResult.email, adminPayload.email)
      assert.equal(getAdminResult.level, adminPayload.level)
      assert.equal(getAdminResult.active, expectedActive)
      hasJustBeenCreated(getAdminResult)
    }

    it('should get active admin', async () => {
      await authGoogle.addAdmin(adminPayload)

      const getAdminResult = await authGoogle.getAdmin(adminPayload.email)

      assertions(getAdminResult)
    })

    it('should not get inactive admin', async () => {
      await authGoogle.addAdmin(adminPayload)
      await authGoogle.updateAdmin(adminPayload.email, { active: false })

      const getAdminResult = await authGoogle.getAdmin(adminPayload.email)

      assert.equal(getAdminResult, undefined)
    })

    it('should get inactive admin', async () => {
      await authGoogle.addAdmin(adminPayload)
      await authGoogle.updateAdmin(adminPayload.email, { active: false })

      const getAdminResult = await authGoogle.getAdmin(adminPayload.email, false)

      assertions(getAdminResult, false)
    })

    it('should get admin using uppercased email', async () => {
      await authGoogle.addAdmin(adminPayload)

      const getAdminResult = await authGoogle.getAdmin(adminPayload.email.toUpperCase())

      assertions(getAdminResult)
    })

    it('should get admin using id', async () => {
      const adminCreationResult = await authGoogle.addAdmin(adminPayload)

      const getAdminResult = await authGoogle.getAdmin(adminCreationResult.id, true, true)

      assertions(getAdminResult)
    })
  })

  describe('fetchMotivationsPrivilege permission', () => {
    it('should add admin successfully with fetchMotivationsPrivilege', async () => {
      await authGoogle.addAdmin({
        ...testAdminWithForms,
        fetchMotivationsPrivilege: true
      })

      const res = await authGoogle.getAdmin(testAdminEmail)

      assert.strictEqual(res.fetchMotivationsPrivilege, 1)
    })

    it('should throw error when adding admin with fetchMotivationsPrivilege not being boolean', async () => {
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

    it('should edit admin successfully with fetchMotivationsPrivilege', async () => {
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

    it('should throw error when editing admin with fetchMotivationsPrivilege not being boolean', async () => {
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

    it('should return true when admin has fetch motivations privilege', async () => {
      await authGoogle.addAdmin({
        ...testAdminWithForms,
        level: 1,
        fetchMotivationsPrivilege: true
      })

      const res = await authGoogle.checkAdmHasFetchMotivationsPrivilege(testAdminEmail)

      assert.ok(res)
    })

    it('should return false when admin does not have fetch motivations privilege', async () => {
      await authGoogle.addAdmin({
        ...testAdminWithForms,
        level: 1,
        fetchMotivationsPrivilege: false
      })

      const res = await authGoogle.checkAdmHasFetchMotivationsPrivilege(testAdminEmail)

      assert.ok(!res)
    })
  })
})
