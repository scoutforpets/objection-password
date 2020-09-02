/* eslint-env jest */
const bcrypt = require('bcrypt')
const { transactionPerTest } = require('objection-transactional-tests')
const { Model } = require('objection')
const Knex = require('knex')
const objectionPassword = require('./index')

// Set up knex
const knex = Knex({
  client: 'sqlite3',
  connection: {
    filename: ':memory:'
  },
  useNullAsDefault: true
})

// Bind knex instance to objection
Model.knex(knex)

const ObjectionPassword = objectionPassword() // Mixin with default options.

// Objection model using default options
class SampleModel extends ObjectionPassword(Model) {
  static get tableName () {
    return 'sample_model'
  }
}

beforeAll(async () => {
  await knex.schema.createTable('sample_model', (table) => {
    table.increments()
    table.string('name')
    table.string('password')
  })
  transactionPerTest()
})

afterAll(async () => {
  await knex.schema.dropTable('sample_model')
  knex.destroy()
})

describe('$beforeInsert', () => {
  it('does not store the password in plaintext', async () => {
    const password = 'hunter1'
    const instance = await SampleModel.query().insert({ name: 'Dominic', password })

    expect(instance.password).not.toEqual(password)
  })

  it('stores a verifiable password', async () => {
    const password = 'hunter1'
    const instance = await SampleModel.query().insert({ name: 'Dominic', password })

    expect(await instance.verifyPassword(password)).toBe(true)
  })

  it('does not allow an empty password', async () => {
    const insertQuery = SampleModel.query().insert({ name: 'Dominic', password: '' })
    expect(insertQuery).rejects.toThrowError()
  })

  it('throws an error when attempting to hash a bcrypt hash', async () => {
    const insertQuery = SampleModel.query().insert({
      name: 'Dominic',
      password: '$2a$12$sWSdI13BJ5ipPca/f8KTF.k4eFKsUtobfWdTBoQdj9g9I8JfLmZty'
    })
    expect(insertQuery).rejects.toThrowError()
  })
})

describe('$beforeUpdate', () => {
  it('does not store the password in plaintext after update', async () => {
    const original = 'hunter1'
    const updated = 'qwerty'

    const instance = await SampleModel.query().insert({ name: 'Dominic', password: original })
    await instance.$query().patch({ password: updated })

    expect(instance.password).not.toEqual(original)
    expect(instance.password).not.toEqual(updated)
  })

  it('creates new hash when updating password', async () => {
    const original = 'hunter1'
    const updated = 'qwerty'

    const instance = await SampleModel.query().insert({ name: 'Dominic', password: original })
    const bcryptSpy = jest.spyOn(bcrypt, 'hash')
    await instance.$query().patch({ password: updated })

    expect(bcryptSpy).toHaveBeenCalledTimes(1)
    expect(await instance.verifyPassword(updated)).toBe(true)
    expect(await instance.verifyPassword(original)).toBe(false)
  })

  it('ignores hashing password field when patching a record where password is not updated', async () => {
    const bcryptSpy = jest.spyOn(bcrypt, 'hash')
    const instance = await SampleModel.query().insert({ name: 'Dominic', password: 'hunter1' })

    await instance.$query().patch({ name: 'Raphael' })

    expect(bcryptSpy).toHaveBeenCalledTimes(1) // Once on creation (and 0 times on patch)
  })

  it('does not allow an empty password', async () => {
    const instance = await SampleModel.query().insert({ name: 'Dominic', password: 'hunter1' })
    const updateQuery = instance.$query().patch({ password: '' })

    expect(updateQuery).rejects.toThrowError()
  })

  it('throws an error when attempting to hash a bcrypt hash', async () => {
    const instance = await SampleModel.query().insert({ name: 'Dominic', password: 'hunter1' })
    const updateQuery = instance.$query().patch({
      password: '$2a$12$sWSdI13BJ5ipPca/f8KTF.k4eFKsUtobfWdTBoQdj9g9I8JfLmZty'
    })

    expect(updateQuery).rejects.toThrowError()
  })
})

describe('options overrides', () => {
  const generateCustomModel = (CustomizedMixin) => {
    return class extends CustomizedMixin(Model) {
      static get tableName () {
        return 'sample_model'
      }
    }
  }

  it('can allow empty string password inserts', async () => {
    const CustomizedMixin = objectionPassword({ allowEmptyPassword: true })
    const CustomModel = generateCustomModel(CustomizedMixin)

    const instance = await CustomModel.query().insert({ name: 'Dominic', password: '' })

    expect(instance.password).toBe('')
  })

  it('can make passwords optional', async () => {
    const CustomizedMixin = objectionPassword({ allowEmptyPassword: true })
    const CustomModel = generateCustomModel(CustomizedMixin)

    const instance = await CustomModel.query().insert({ name: 'Dominic' })

    expect(instance.password).not.toBeDefined()
  })

  it('can allow updating a password to an empty string', async () => {
    const CustomizedMixin = objectionPassword({ allowEmptyPassword: true })
    const CustomModel = generateCustomModel(CustomizedMixin)

    const instance = await CustomModel.query().insert({ name: 'Dominic', password: 'hunter1' })
    await instance.$query().patch({ password: '' })

    expect(instance.password).toBe('')
  })

  it('can allow unsetting a password (set to null)', async () => {
    const CustomizedMixin = objectionPassword({ allowEmptyPassword: true })
    const CustomModel = generateCustomModel(CustomizedMixin)

    const instance = await CustomModel.query().insert({ name: 'Dominic', password: 'hunter1' })
    await instance.$query().patch({ password: null })

    expect(instance.password).toBe(null)
  })

  it('can override the default password field', async () => {
    // Use the name field instead of the password field as the password used by the plugin
    const CustomizedMixin = objectionPassword({ passwordField: 'name' })
    const CustomModel = generateCustomModel(CustomizedMixin)

    const name = 'Dominic'
    const password = 'hunter1'
    const instance = await CustomModel.query().insert({ name, password })

    expect(await instance.verifyPassword(password)).toBe(false)
    expect(await instance.verifyPassword(name)).toBe(true)
  })

  it('can set the number of bcrypt hashing rounds', async () => {
    // Expect to be called with 13 instead of 12
    const CustomizedMixin = objectionPassword({ rounds: 13 })
    const CustomModel = generateCustomModel(CustomizedMixin)

    const bcryptSpy = jest.spyOn(bcrypt, 'hash')

    const password = 'hunter1'
    await CustomModel.query().insert({ name: 'Dominic', password })

    expect(bcryptSpy).toHaveBeenCalledWith(password, 13)
  })
})

describe('isBcryptHash', () => {
  it('returns true when given a bcrypt hash', async () => {
    expect(SampleModel.isBcryptHash(await bcrypt.hash('hello world', 12))).toBe(true)
  })

  it('returns false when given a regular string', () => {
    expect(SampleModel.isBcryptHash('hello world')).toBe(false)
  })
})
