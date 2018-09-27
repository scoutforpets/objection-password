'use strict'

import test from 'ava'

const Bcrypt = require('../index')()
const Knex = require('knex')
const Model = require('objection').Model

const knex = Knex({
  client: 'sqlite3',
  connection: {
    filename: ':memory:'
  },
  useNullAsDefault: true
})

// bind knex instance to objection
Model.knex(knex)

// objection models
class Dog extends Bcrypt(Model) {
  static get tableName () {
    return 'dog'
  }
}

// tests
test.before(async (t) => {
  await knex.schema.createTable('dog', (table) => {
    table.increments()
    table.string('name')
    table.string('password')
  })
})

test('hashes and verifies a password', async (t) => {
  const password = 'Turtle123!'
  const dog = await Dog.query().insert({ name: 'JJ', password })
  t.true(await dog.verifyPassword(password))
})

test('creates new hash when updating password', async (t) => {
  const original = 'Turtle123!'
  const updated = 'Monkey69!'

  const dog = await Dog.query().insert({ name: 'JJ', password: original })
  t.true(await dog.verifyPassword(original))

  const updatedDog = await dog.$query().patchAndFetchById(dog.id, { password: updated })
  t.true(await updatedDog.verifyPassword(updated))
})

test('ignores hashing password field when patching a record where password isn\'t updated', async (t) => {
  const dog = await Dog.query().insert({ name: 'JJ', password: 'Turtle123!' })

  // update name only
  await dog.$query().patchAndFetchById(dog.id, { name: 'Jumbo Jet' })

  t.pass()
})

test('do not allow empty password', async (t) => {
  const password = ''
  const dog = Dog.query().insert({ name: 'JJ', password })
  const error = await t.throws(dog)
  t.is(error.message, 'password must not be empty')
})

test('allow empty password', async (t) => {
  const BcryptWithOptions = require('../index')({ allowEmptyPassword: true })

  class Mouse extends BcryptWithOptions(Model) {
    static get tableName () {
      return 'mouse'
    }
  }

  await knex.schema.createTable('mouse', (table) => {
    table.increments()
    table.string('name')
    table.string('password')
  })

  const password = ''
  const mouse = await Mouse.query().insert({ name: 'Ricky', password })

  t.falsy(mouse.password)
})

test('throws an error when attempting to hash a bcrypt hash', async (t) => {
  const dog = Dog.query().insert({ name: 'JJ', password: '$2a$12$sWSdI13BJ5ipPca/f8KTF.k4eFKsUtobfWdTBoQdj9g9I8JfLmZty' })
  const error = await t.throws(dog)
  t.is(error.message, 'bcrypt tried to hash another bcrypt hash')
})

test('can override default password field', async (t) => {
  const BcryptWithOptions = require('../index')({ passwordField: 'hash' })

  class Cat extends BcryptWithOptions(Model) {
    static get tableName () {
      return 'cat'
    }
  }

  await knex.schema.createTable('cat', (table) => {
    table.increments()
    table.string('name')
    table.string('hash')
  })

  const password = 'Turtle123!'
  const cat = await Cat.query().insert({ name: 'Maude', hash: password })

  t.truthy(cat.hash)
  t.true(await cat.verifyPassword(password))
})
