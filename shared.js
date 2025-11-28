const DB_TABLES = Object.freeze({
  ADMIN_USERS: 'admin_users',
  ADMIN_LEVEL_DAILY_LIMITS: 'admin_level_daily_limits'
})

const VALID_DAILY_LIMIT_CATEGORIES = Object.freeze(['opened', 'displayed'])

const MIN_ADMIN_LEVEL = 0

const MAX_ADMIN_LEVEL = 4

module.exports = {
  DB_TABLES,
  VALID_DAILY_LIMIT_CATEGORIES,
  MIN_ADMIN_LEVEL,
  MAX_ADMIN_LEVEL
}
