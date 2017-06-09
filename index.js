'use strict';

const Bcrypt = require('bcrypt');

// https://paragonie.com/blog/2016/02/how-safely-store-password-in-2016
const RECOMMENDED_ROUNDS = 12;

module.exports = (options) => {

  // Provide good defaults for the options if possible.
    options = Object.assign({
        passwordField: 'password',
        rounds: RECOMMENDED_ROUNDS
    }, options);

  // Return the mixin. If your plugin doesn't take options, you can simply export
  // the mixin. The factory function is not needed.
    return (Model) => {

        class BcryptModel extends Model {

            $beforeInsert(context) {

                const maybePromise = super.$beforeInsert(context);

                return Promise.resolve(maybePromise).then(() => {

                    // hash the password
                    return this.constructor.generateHash(this[options.passwordField], options.rounds).then((hash) => {
                        if (hash) {
                            this[options.passwordField] = hash;
                        }
                    });
                });
            }

            $beforeUpdate(opt, context) {

                const maybePromise = super.$beforeUpdate(context);

                return Promise.resolve(maybePromise).then(() => {

                    // hash the password
                    return this.constructor.generateHash(this[options.passwordField], options.rounds, true).then((hash) => {
                        if (hash) {
                            this[options.passwordField] = hash;
                        }
                    });
                });
            }

            /**
             * Generates a Bcrypt hash
             * @param  {String}  password         the password...
             * @param  {Number}  rounds           the number of rounds to use when hashing (default = 12)
             * @param  {Boolean} [isUpdate=false] determines whether to check if bcrypt hash is being re-hashed
             * @return {String}                   returns the hash or null
             */
            static generateHash(password, rounds, isUpdate = false) {

                if (password) {

                    if (isUpdate && this.detectBcrypt(password)) {
                        throw new Error('Bcrypt tried to hash another bcrypt hash');
                    }

                    return Bcrypt.hash(password, options.rounds);
                }

                return Promise.resolve();
            }

            /**
             * Detect rehashing for avoiding undesired effects
             * @param {String} str A string to be checked
             * @return {Boolean} True if the str seems to be a bcrypt hash
             */
            static detectBcrypt(str) {

                const protocol = str.split('$');

                // Ex $2a$12$K2CtDP7zSGOKgjXjxD9SYey9mSZ9Udio9C95K6wCKZewSP9oBWyPO
                return protocol.length === 4 &&
                    protocol[0] === '' &&
                    ['2a', '2b', '2y'].indexOf(protocol[1]) > -1 &&
                    /^\d+$/.test(protocol[2]) &&
                    protocol[3].length === 53;
            }
        }

        return BcryptModel;
    };
};
