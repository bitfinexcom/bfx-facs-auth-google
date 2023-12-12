'use strict'

class UserError extends Error {
  constructor (message) {
    super(message)
    this.name = message
    this.type = 'UserError'
  }
}

module.exports = {
  UserError
}
