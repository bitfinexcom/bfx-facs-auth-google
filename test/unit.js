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

describe('index', () => {
  beforeEach(async () => {
    cleanup()
    await new Promise((resolve) => authGoogle.start(resolve))
  })

  afterEach(async () => {
    await new Promise((resolve) => authGoogle.stop(resolve))
  })

  describe('forms field', () => {
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

  describe('daily limits', () => {
    const level = 0
    const category = VALID_DAILY_LIMIT_CATEGORIES[0]

    const assertUserError = async (fn, msg) => {
      try {
        await fn()
        throw new Error('SHOULD_NOT_REACH_HERE')
      } catch (e) {
        assert.ok(e instanceof UserError)
        assert.strictEqual(e.message, msg)
      }
    }

    const assertAssertionError = async (fn, msg) => {
      try {
        await fn()
        throw new Error('SHOULD_NOT_REACH_HERE')
      } catch (e) {
        assert.ok(e instanceof assert.AssertionError)
        assert.strictEqual(e.message, msg)
      }
    }

    describe('for admin levels', () => {
      describe('creating/updatig daily limits for an admin level', () => {
        it('should create succesfully an admin level daily limit', async () => {
          const levelDailyLimit = await authGoogle.setAdminLevelDailyLimit(level, category, { alert: 0, block: 0 })
          assert.ok(levelDailyLimit)
        })

        it('should update succesfully an admin level daily limit config', async () => {
          const levelDailyLimit = await authGoogle.setAdminLevelDailyLimit(level, category, { alert: 0, block: 0 })
          assert.ok(levelDailyLimit)
          const update = { alert: 10, block: 20 }
          const updateResult = await authGoogle.setAdminLevelDailyLimit(level, category, update)
          assert.ok(updateResult)
          const retrievedLevelDailyLimit = await authGoogle.getAdminLevelDailyLimit(level, category)
          assert.deepStrictEqual(retrievedLevelDailyLimit, update)
        })

        it('should throw error when trying to set an admin level daily limit with non numeric value for admin level', async () => {
          const invalidAdminLevel = 'non numeric value'
          await assertUserError(
            async () => authGoogle.setAdminLevelDailyLimit(invalidAdminLevel, category, { alert: 0, block: 0 }),
            `"${invalidAdminLevel}" as admin level is invalid`
          )
        })

        it('should throw error when trying to set an admin level daily limit with a numeric admin level beyond the valid range (between 0 and 4, inclusive)', async () => {
          const invalidAdminLevel = -1
          await assertUserError(
            async () => authGoogle.setAdminLevelDailyLimit(invalidAdminLevel, category, { alert: 0, block: 0 }),
            `"${invalidAdminLevel}" as admin level is invalid`
          )
        })

        it('should throw error when trying to set an admin level daily limit with an invalid category', async () => {
          const invalidCategory = 'some invalid category'
          await assertUserError(
            async () => authGoogle.setAdminLevelDailyLimit(level, invalidCategory, { alert: 0, block: 0 }),
            `"${invalidCategory}" as daily limit category value is invalid`
          )
        })

        it('should throw error when trying to set an admin level daily limit with neither alert nor block', async () => {
          await assertUserError(
            async () => authGoogle.setAdminLevelDailyLimit(level, category),
            'Neither alert nor block values are provided'
          )
        })

        it('should throw error when trying to create an admin level daily limit using only alert without block', async () => {
          await assertUserError(
            async () => authGoogle.setAdminLevelDailyLimit(level, category, { alert: 0 }),
            'When creating an admin level daily limit both alert and block must be provided'
          )
        })

        it('should throw error when trying to create an admin level daily limit using only block without alert', async () => {
          await assertUserError(
            async () => authGoogle.setAdminLevelDailyLimit(level, category, { block: 0 }),
            'When creating an admin level daily limit both alert and block must be provided'
          )
        })

        it('should throw error when trying to set an admin level daily limit with alert being not integer', async () => {
          const invalidAlert = 1.1
          await assertUserError(
            async () => authGoogle.setAdminLevelDailyLimit(level, category, { alert: invalidAlert, block: 0 }),
            'When alert value is provided, must be integer and greater or equal to zero'
          )
        })

        it('should throw error when trying to set an admin level daily limit with alert being an integer lower than zero', async () => {
          const invalidAlert = -1
          await assertUserError(
            async () => authGoogle.setAdminLevelDailyLimit(level, category, { alert: invalidAlert, block: 0 }),
            'When alert value is provided, must be integer and greater or equal to zero'
          )
        })

        it('should throw error when trying to set an admin level daily limit with alert being not integer', async () => {
          const invalidBlock = 1.1
          await assertUserError(
            async () => authGoogle.setAdminLevelDailyLimit(level, category, { alert: 0, block: invalidBlock }),
            'When block value is provided, must be integer and greater or equal to zero'
          )
        })

        it('should throw error when trying to set an admin level daily limit with alert being an integer lower than zero', async () => {
          const invalidBlock = -1
          await assertUserError(
            async () => authGoogle.setAdminLevelDailyLimit(level, category, { alert: 0, block: invalidBlock }),
            'When block value is provided, must be integer and greater or equal to zero'
          )
        })
      })

      describe('retrieving daily limits', () => {
        it('should retrieve succesfully an admin level daily limit config', async () => {
          const levelDailyLimit = await authGoogle.setAdminLevelDailyLimit(level, category, { alert: 0, block: 0 })
          assert.ok(levelDailyLimit)
          const retrievedLevelDailyLimit = await authGoogle.getAdminLevelDailyLimit(level, category)
          assert.deepStrictEqual(retrievedLevelDailyLimit, { alert: 0, block: 0 })
        })

        it('should throw error when trying to get an admin level daily limit config with non numeric value for admin level', async () => {
          const invalidAdminLevel = 'non numeric value'
          await assertUserError(
            async () => authGoogle.getAdminLevelDailyLimit(invalidAdminLevel, category),
            `"${invalidAdminLevel}" as admin level is invalid`
          )
        })

        it('should throw error when trying to get an admin level daily limit config with a numeric admin level beyond the valid range (between 0 and 4, inclusive)', async () => {
          const invalidAdminLevel = -1
          await assertUserError(
            async () => authGoogle.getAdminLevelDailyLimit(invalidAdminLevel, category, { alert: 0, block: 0 }),
            `"${invalidAdminLevel}" as admin level is invalid`
          )
        })

        it('should throw error when trying to get an admin level daily limit with an invalid category', async () => {
          const invalidCategory = 'some invalid category'
          await assertUserError(
            async () => authGoogle.getAdminLevelDailyLimit(level, invalidCategory),
            `"${invalidCategory}" as daily limit category value is invalid`
          )
        })

        it('should retrieve succesfully all configs associated to an admin level', async () => {
          const category1 = VALID_DAILY_LIMIT_CATEGORIES[0]
          const levelDailyLimit1 = await authGoogle.setAdminLevelDailyLimit(level, category1, { alert: 0, block: 0 })
          assert.ok(levelDailyLimit1)
          const category2 = VALID_DAILY_LIMIT_CATEGORIES[1]
          const levelDailyLimit2 = await authGoogle.setAdminLevelDailyLimit(level, category2, { alert: 30, block: 50 })
          assert.ok(levelDailyLimit2)
          const retrievedLevelDailyLimits = await authGoogle.getDailyLimitsByAdminLevel(level)
          assert.deepStrictEqual(retrievedLevelDailyLimits, {
            [category1]: { alert: 0, block: 0 },
            [category2]: { alert: 30, block: 50 }
          })
        })

        it('should throw error when trying to get all daily limit configs associated to an admin level with non numeric value for admin level', async () => {
          const invalidAdminLevel = 'non numeric value'
          await assertUserError(
            async () => authGoogle.getDailyLimitsByAdminLevel(invalidAdminLevel),
            `"${invalidAdminLevel}" as admin level is invalid`
          )
        })

        it('should throw error when trying to get all daily limit configs associated to an admin level with a numeric admin level beyond the valid range (between 0 and 4, inclusive)', async () => {
          const invalidAdminLevel = -1
          await assertUserError(
            async () => authGoogle.getDailyLimitsByAdminLevel(invalidAdminLevel),
            `"${invalidAdminLevel}" as admin level is invalid`
          )
        })

        it('should retrieve succesfully all configs associated to a daily limit category', async () => {
          const level1 = 0
          const levelDailyLimit1 = await authGoogle.setAdminLevelDailyLimit(level1, category, { alert: 0, block: 0 })
          assert.ok(levelDailyLimit1)
          const level2 = 1
          const levelDailyLimit2 = await authGoogle.setAdminLevelDailyLimit(level2, category, { alert: 30, block: 50 })
          assert.ok(levelDailyLimit2)
          const retrievedLevelDailyLimits = await authGoogle.getDailyLimitsByCategory(category)
          assert.deepStrictEqual(retrievedLevelDailyLimits, {
            [level1]: { alert: 0, block: 0 },
            [level2]: { alert: 30, block: 50 }
          })
        })

        it('should throw error when trying to get all daily limit configs associated to an admin level with non numeric value for admin level', async () => {
          const invalidCategory = 'invalid category'
          await assertUserError(
            async () => authGoogle.getDailyLimitsByCategory(invalidCategory),
            `"${invalidCategory}" as daily limit category value is invalid`
          )
        })
      })

      describe('removing daily limits', () => {
        it('should remove successfully all daily limits associated to an admin level', async () => {
          const level0 = 0
          const level1 = 1
          const category0 = VALID_DAILY_LIMIT_CATEGORIES[0]
          const category1 = VALID_DAILY_LIMIT_CATEGORIES[1]
          await authGoogle.setAdminLevelDailyLimit(level0, category0, { alert: 0, block: 0 })
          await authGoogle.setAdminLevelDailyLimit(level0, category1, { alert: 0, block: 0 })
          await authGoogle.setAdminLevelDailyLimit(level1, category0, { alert: 0, block: 0 })
          await authGoogle.removeAdminLevelDailyLimits(level0)
          assert.strictEqual(await authGoogle.getAdminLevelDailyLimit(level0, category0), null)
          assert.strictEqual(await authGoogle.getAdminLevelDailyLimit(level0, category1), null)
          assert.deepStrictEqual(await authGoogle.getAdminLevelDailyLimit(level1, category0), { alert: 0, block: 0 })
        })

        it('should throw error when trying to remove admin level daily limits with non numeric value for admin level', async () => {
          const invalidAdminLevel = 'non numeric value'
          await assertUserError(
            async () => authGoogle.removeAdminLevelDailyLimits(invalidAdminLevel),
            `"${invalidAdminLevel}" as admin level is invalid`
          )
        })

        it('should throw error when trying to remove admin level daily limits with a numeric admin level beyond the valid range (between 0 and 4, inclusive)', async () => {
          const invalidAdminLevel = -1
          await assertUserError(
            async () => authGoogle.removeAdminLevelDailyLimits(invalidAdminLevel),
            `"${invalidAdminLevel}" as admin level is invalid`
          )
        })
      })
    })

    describe('for admin users', () => {
      const dailyLimitConfig = VALID_DAILY_LIMIT_CATEGORIES.reduce((acc, curr) => {
        acc[curr] = { alert: 0, block: 0 }
        return acc
      }, {})

      const adminWithDailyLimitConfig = {
        email: testAdminEmail,
        password: 'test123',
        level,
        dailyLimitConfig
      }

      const dailyLimitConfigErrMsg = 'dailyLimitConfig must be a DailyLimitConfigsByCategory object'

      const assertDailyLimitConfig = async (expectedDailyLimitConfig) => {
        const actualDailyLimitConfig = await authGoogle.getAdminUserDailyLimitConfig(testAdminEmail)
        assert.deepStrictEqual(actualDailyLimitConfig, expectedDailyLimitConfig)
      }

      describe('creating admin with dailyLimitConfig', () => {
        it('should create admin user with dailyLimitConfig', async () => {
          await authGoogle.addAdmin(adminWithDailyLimitConfig)
          await assertDailyLimitConfig(dailyLimitConfig)
        })

        it('should throw error when creating admin user with dailyConfig not being an object', async () => {
          await assertAssertionError(
            async () => authGoogle.addAdmin({
              ...adminWithDailyLimitConfig,
              dailyLimitConfig: 'not an object'
            }),
            dailyLimitConfigErrMsg
          )
        })

        it('should throw error when creating admin user with dailyConfig object having an invalid category as key', async () => {
          await assertAssertionError(
            async () => authGoogle.addAdmin({
              ...adminWithDailyLimitConfig,
              dailyLimitConfig: {
                ...dailyLimitConfig,
                invalid_key: { alert: 0, block: 0 }
              }
            }),
            dailyLimitConfigErrMsg
          )
        })

        it('should throw error when creating admin user with dailyConfig object having all valid keys but there is at least one not having both alert and block defined', async () => {
          await assertAssertionError(
            async () => authGoogle.addAdmin({
              ...adminWithDailyLimitConfig,
              dailyLimitConfig: {
                ...dailyLimitConfig,
                [VALID_DAILY_LIMIT_CATEGORIES[0]]: {
                  alert: 0
                }
              }
            }),
            dailyLimitConfigErrMsg
          )
        })

        it('should throw error when creating admin user with dailyConfig object having all valid keys but there is at least one having alert and/or block as not integers', async () => {
          await assertAssertionError(
            async () => authGoogle.addAdmin({
              ...adminWithDailyLimitConfig,
              dailyLimitConfig: {
                ...dailyLimitConfig,
                [VALID_DAILY_LIMIT_CATEGORIES[0]]: {
                  alert: 1.1,
                  block: 0
                }
              }
            }),
            dailyLimitConfigErrMsg
          )
        })

        it('should throw error when creating admin user with dailyConfig object having all valid keys but there is at least one having alert and/or block as negative integers', async () => {
          await assertAssertionError(
            async () => authGoogle.addAdmin({
              ...adminWithDailyLimitConfig,
              dailyLimitConfig: {
                ...dailyLimitConfig,
                [VALID_DAILY_LIMIT_CATEGORIES[0]]: {
                  alert: -1,
                  block: 0
                }
              }
            }),
            dailyLimitConfigErrMsg
          )
        })
      })

      describe('updating admin with dailyLimitConfig', () => {
        it('should update admin user with dailyLimitConfig', async () => {
          await authGoogle.addAdmin(omit(adminWithDailyLimitConfig, ['dailyLimitConfig']))
          await assertDailyLimitConfig(null)
          await authGoogle.updateAdmin(testAdminEmail, { dailyLimitConfig })
          await assertDailyLimitConfig(dailyLimitConfig)
        })

        it('should nullify admin user daily limit config', async () => {
          await authGoogle.addAdmin(adminWithDailyLimitConfig)
          await assertDailyLimitConfig(dailyLimitConfig)
          const result = await authGoogle.removeAdminUserDailyLimitConfig(testAdminEmail)
          assert.ok(result)
          await assertDailyLimitConfig(null)
        })

        it('should throw error when trying to update admin user with dailyConfig not being an object', async () => {
          await assertAssertionError(
            async () => authGoogle.updateAdmin(testAdminEmail, { dailyLimitConfig: 'not an object' }),
            dailyLimitConfigErrMsg
          )
        })

        it('should throw error when trying to update admin user with dailyConfig object having an invalid category as key', async () => {
          await assertAssertionError(
            async () => authGoogle.updateAdmin(testAdminEmail, {
              dailyLimitConfig: {
                ...dailyLimitConfig,
                invalid_key: { alert: 0, block: 0 }
              }
            }),
            dailyLimitConfigErrMsg
          )
        })

        it('should throw error when trying to update admin user with dailyConfig object having all valid keys but there is at least one not having both alert and block defined', async () => {
          await assertAssertionError(
            async () => authGoogle.updateAdmin(testAdminEmail, {
              dailyLimitConfig: {
                ...dailyLimitConfig,
                [VALID_DAILY_LIMIT_CATEGORIES[0]]: {
                  alert: 0
                }
              }
            }),
            dailyLimitConfigErrMsg
          )
        })

        it('should throw error when trying to update admin user with dailyConfig object having all valid keys but there is at least one having alert and/or block as not integers', async () => {
          await assertAssertionError(
            async () => authGoogle.updateAdmin(testAdminEmail, {
              dailyLimitConfig: {
                ...dailyLimitConfig,
                [VALID_DAILY_LIMIT_CATEGORIES[0]]: {
                  alert: 1.1,
                  block: 0
                }
              }
            }),
            dailyLimitConfigErrMsg
          )
        })

        it('should throw error when trying to update admin user with dailyConfig object having all valid keys but there is at least one having alert and/or block as negative integers', async () => {
          await assertAssertionError(
            async () => authGoogle.updateAdmin(testAdminEmail, {
              dailyLimitConfig: {
                ...dailyLimitConfig,
                [VALID_DAILY_LIMIT_CATEGORIES[0]]: {
                  alert: -1,
                  block: 0
                }
              }
            }),
            dailyLimitConfigErrMsg
          )
        })
      })

      describe('retrieving daily limit config', () => {
        it('should return admin user with parsed dailyLimitConfig', async () => {
          await authGoogle.addAdmin(adminWithDailyLimitConfig)
          const res = await authGoogle.getAdmin(testAdminEmail)
          assert.deepStrictEqual(res.dailyLimitConfig, dailyLimitConfig)
        })

        it('should retrieve the daily limit config of a given admin user', async () => {
          await authGoogle.addAdmin(adminWithDailyLimitConfig)
          await assertDailyLimitConfig(dailyLimitConfig)
          const retrievedDailyLimitConfig = await authGoogle.getAdminUserDailyLimitConfig(adminWithDailyLimitConfig.email)
          assert.deepStrictEqual(retrievedDailyLimitConfig, dailyLimitConfig)
        })

        it('should retrieve the daily limit config of a given admin user when this does not have it defined but its level does', async () => {
          const levelDailyLimitCreationResult = await authGoogle.setAdminLevelDailyLimit(level, category, { alert: 0, block: 0 })
          assert.ok(levelDailyLimitCreationResult)
          await authGoogle.addAdmin(omit(adminWithDailyLimitConfig, ['dailyLimitConfig']))
          const retrievedDailyLimitConfig = await authGoogle.getAdminUserDailyLimitConfig(adminWithDailyLimitConfig.email)
          assert.deepStrictEqual(retrievedDailyLimitConfig, { [category]: { alert: 0, block: 0 } })
        })

        it('should retrieve null when trying to fetch admin user daily limit config which does not have it defined but its level does but we are passing down the flag for disabling falling back to that value', async () => {
          const levelDailyLimitCreationResult = await authGoogle.setAdminLevelDailyLimit(level, category, { alert: 0, block: 0 })
          assert.ok(levelDailyLimitCreationResult)
          await authGoogle.addAdmin(omit(adminWithDailyLimitConfig, ['dailyLimitConfig']))
          const retrievedDailyLimitConfig = await authGoogle.getAdminUserDailyLimitConfig(adminWithDailyLimitConfig.email, false)
          assert.equal(retrievedDailyLimitConfig, null)
        })

        it('should retrieve null when no daily limit has been set for the admin and its level either', async () => {
          await authGoogle.addAdmin(omit(adminWithDailyLimitConfig, ['dailyLimitConfig']))
          await assertDailyLimitConfig(null)
          const retrievedDailyLimitConfig = await authGoogle.getAdminUserDailyLimitConfig(adminWithDailyLimitConfig.email)
          assert.deepStrictEqual(retrievedDailyLimitConfig, null)
        })

        it('should throw error when trying to retrieve a daily limit config for a non existing admin', async () => {
          assertUserError(
            async () => authGoogle.getAdminUserDailyLimitConfig('non-existing-address@bitfinex.com'),
            'ADMIN_ACCOUNT_DOES_NOT_EXIST_OR_IS_NOT_ACTIVE'
          )
        })
      })

      describe('removing admin daily limit config', () => {
        it('should remove daily limit config associated to an admin', async () => {
          await authGoogle.addAdmin(adminWithDailyLimitConfig)
          await assertDailyLimitConfig(dailyLimitConfig)
          await authGoogle.removeAdminUserDailyLimitConfig(adminWithDailyLimitConfig.email)
          await assertDailyLimitConfig(null)
        })

        it('should throw error when trying to remove a daily limit config for a non existing admin', async () => {
          assertUserError(
            async () => authGoogle.removeAdminUserDailyLimitConfig('non-existing-address@bitfinex.com'),
            'ADMIN_ACCOUNT_DOES_NOT_EXIST_OR_IS_NOT_ACTIVE'
          )
        })
      })
    })
  })
})
