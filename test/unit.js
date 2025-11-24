/* eslint-env mocha */

'use strict'

const assert = require('assert')
const fs = require('fs')
const path = require('path')

const conf = require('./config/facs/auth-google.config')

const AuthGoogle = require('../')
const { omit } = require('@bitfinexcom/lib-js-util-base')
const { VALID_DAILY_LIMIT_CATEGORIES } = require('../shared')
const { UserError } = require('../errors')

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

  describe.only('daily limits', () => {
    describe('for admin levels', () => {
      const level = 0
      const category = VALID_DAILY_LIMIT_CATEGORIES[0]

      it('should create succesfully a level daily limit', async () => {
        const levelDailyLimit = await authGoogle.setLevelDailyLimit(level, category, { alert: 0, block: 0 })
        assert.ok(levelDailyLimit)
      })

      // TODO: fix this test, it's not working, for some reason getLevelDailyLimit is returning undefined, check internal SELECT behavior
      it('should retrieve succesfully a level daily limit', async () => {
        const levelDailyLimit = await authGoogle.setLevelDailyLimit(level, category, { alert: 0, block: 0 })
        assert.ok(levelDailyLimit)
        const retrievedLevelDailyLimit = await authGoogle.getLevelDailyLimit(level, category)
        assert.ok(retrievedLevelDailyLimit)
      })

      it('should update succesfully a level daily limit', async () => {
        const levelDailyLimit = await authGoogle.setLevelDailyLimit(level, category, { alert: 0, block: 0 })
        assert.ok(levelDailyLimit)
        await authGoogle.setLevelDailyLimit(level, category, { alert: 10, block: 20 })
        assert.ok(levelDailyLimit)
      })

      it('should throw error when trying to set a level daily limit with non numeric value for admin level', async () => {
        const invalidAdminLevel = 'non numeric value'
        try {
          await authGoogle.setLevelDailyLimit(invalidAdminLevel, category, { alert: 0, block: 0 })
          throw new Error('SHOULD_NOT_REACH_HERE')
        } catch (e) {
          assert.ok(e instanceof UserError)
          assert.strictEqual(e.message, `"${invalidAdminLevel}" as admin level is invalid`)
        }
      })

      it('should throw error when trying to set a level daily limit with a numeric admin level beyond the valid range (between 0 and 4, inclusive)', async () => {
        const invalidAdminLevel = -1
        try {
          await authGoogle.setLevelDailyLimit(invalidAdminLevel, category, { alert: 0, block: 0 })
          throw new Error('SHOULD_NOT_REACH_HERE')
        } catch (e) {
          assert.ok(e instanceof UserError)
          assert.strictEqual(e.message, `"${invalidAdminLevel}" as admin level is invalid`)
        }
      })

      it('should throw error when trying to set a level daily limit with an invalid category', async () => {
        const invalidCategory = 'some invalid category'
        try {
          await authGoogle.setLevelDailyLimit(level, invalidCategory, { alert: 0, block: 0 })
          throw new Error('SHOULD_NOT_REACH_HERE')
        } catch (e) {
          assert.ok(e instanceof UserError)
          assert.strictEqual(e.message, `"${invalidCategory}" as daily limit category value is invalid`)
        }
      })

      it('should throw error when trying to set a level daily limit with neither alert nor block', async () => {
        try {
          await authGoogle.setLevelDailyLimit(level, category)
          throw new Error('SHOULD_NOT_REACH_HERE')
        } catch (e) {
          assert.ok(e instanceof UserError)
          assert.strictEqual(e.message, 'Neither alert nor block values are provided')
        }
      })

      it('should throw error when trying to create a level daily limit using only alert without block', async () => {
        try {
          await authGoogle.setLevelDailyLimit(level, category, { alert: 0 })
          throw new Error('SHOULD_NOT_REACH_HERE')
        } catch (e) {
          assert.ok(e instanceof UserError)
          assert.strictEqual(e.message, 'When creating a level daily limit both alert and block must be provided')
        }
      })

      it('should throw error when trying to create a level daily limit using only block without alert', async () => {
        try {
          await authGoogle.setLevelDailyLimit(level, category, { block: 0 })
          throw new Error('SHOULD_NOT_REACH_HERE')
        } catch (e) {
          assert.ok(e instanceof UserError)
          assert.strictEqual(e.message, 'When creating a level daily limit both alert and block must be provided')
        }
      })

      it('should throw error when trying to set a level daily limit with alert being not integer', async () => {
        const invalidAlert = 1.1
        try {
          await authGoogle.setLevelDailyLimit(level, category, { alert: invalidAlert, block: 0 })
          throw new Error('SHOULD_NOT_REACH_HERE')
        } catch (e) {
          assert.ok(e instanceof UserError)
          assert.strictEqual(e.message, 'When alert value is provided, must be integer and greater or equal to zero')
        }
      })

      it('should throw error when trying to set a level daily limit with alert being an integer lower than zero', async () => {
        const invalidAlert = -1
        try {
          await authGoogle.setLevelDailyLimit(level, category, { alert: invalidAlert, block: 0 })
          throw new Error('SHOULD_NOT_REACH_HERE')
        } catch (e) {
          assert.ok(e instanceof UserError)
          assert.strictEqual(e.message, 'When alert value is provided, must be integer and greater or equal to zero')
        }
      })

      it('should throw error when trying to set a level daily limit with alert being not integer', async () => {
        const invalidBlock = 1.1
        try {
          await authGoogle.setLevelDailyLimit(level, category, { alert: 0, block: invalidBlock })
          throw new Error('SHOULD_NOT_REACH_HERE')
        } catch (e) {
          assert.ok(e instanceof UserError)
          assert.strictEqual(e.message, 'When block value is provided, must be integer and greater or equal to zero')
        }
      })

      it('should throw error when trying to set a level daily limit with alert being an integer lower than zero', async () => {
        const invalidBlock = -1
        try {
          await authGoogle.setLevelDailyLimit(level, category, { alert: 0, block: invalidBlock })
          throw new Error('SHOULD_NOT_REACH_HERE')
        } catch (e) {
          assert.ok(e instanceof UserError)
          assert.strictEqual(e.message, 'When block value is provided, must be integer and greater or equal to zero')
        }
      })

      // TODO: implement remaining error cases tests
    })

    // TODO: implement tests related to managing daily limit config of admins
  })
})
