'use strict'

const Bcrypt = require('bcrypt')

const RECOMMENDED_ROUNDS = 12

const REGEXP = /^\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53}$/

module.exports = (options) => {
  // Provide good defaults for the options if possible.
  options = Object.assign({
    allowEmptyPassword: false,
    passwordField: 'password',
    rounds: RECOMMENDED_ROUNDS
  }, options)

  // Return the mixin. If your plugin doesn't take options, you can simply export
  // the mixin. The factory function is not needed.
  return (Model) => {
    return class extends Model {
      $beforeInsert (context) {
        const maybePromise = super.$beforeInsert(context)

        return Promise.resolve(maybePromise).then(() => {
          // hash the password
          return this.generateHash()
        })
      }

      $beforeUpdate (queryOptions, context) {
        const maybePromise = super.$beforeUpdate(queryOptions, context)

        return Promise.resolve(maybePromise).then(() => {
          if (queryOptions.patch && this[options.passwordField] === undefined) {
            return
          }

          // hash the password
          return this.generateHash()
        })
      }

      /**
             * Compares a password to a Bcrypt hash
             * @param  {String}             password  the password...
             * @return {Promise.<Boolean>}            whether or not the password was verified
             */
      verifyPassword (password) {
        return Bcrypt.compare(password, this[options.passwordField])
      }

      /**
             * Generates a Bcrypt hash
             * @return {Promise.<(String|void)>}  returns the hash or null
             */
      generateHash () {
        const password = this[options.passwordField]

        if (password) {
          if (this.constructor.isBcryptHash(password)) {
            throw new Error('bcrypt tried to hash another bcrypt hash')
          }

          return Bcrypt.hash(password, options.rounds).then((hash) => {
            this[options.passwordField] = hash
          })
        }

        // throw an error if empty passwords aren't allowed
        if (!options.allowEmptyPassword) {
          throw new Error('password must not be empty')
        }

        return Promise.resolve()
      }

      /**
             * Detect rehashing for avoiding undesired effects
             * @param {String} str A string to be checked
             * @return {Boolean} True if the str seems to be a bcrypt hash
             */
      static isBcryptHash (str) {
        return REGEXP.test(str)
      }
    }
  }
}
