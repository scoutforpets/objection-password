const Knex = require('knex')
const { transaction, Model } = require('objection')

global.beforeAll(async () => {
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

  global.knex = knex
  global.txn = null
})

global.beforeEach(async () => {
  global.txn = await transaction.start(knex)
  Model.knex(global.txn)
})

global.afterEach(async () => {
  await global.txn.rollback()
  Model.knex(knex)
})

global.afterAll(async () => {
  global.knex.destroy()
})
