/* eslint-env mocha */

'use strict'

const assert = require('assert')

const AuthGoogle = require('../')

const ctx = {root: './test'}
const caller = {ctx: ctx}
const authGoogle = new AuthGoogle(caller, {}, ctx)


