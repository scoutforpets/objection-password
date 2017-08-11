'use strict';

const Bcrypt = require('bcrypt');

const RECOMMENDED_ROUNDS = 12;

module.exports = (options) => {

    // Provide good defaults for the options if possible.
    options = Object.assign({
        allowEmptyPassword: false,
        passwordField: 'password',
        rounds: RECOMMENDED_ROUNDS
    }, options);

    // Return the mixin. If your plugin doesn't take options, you can simply export
    // the mixin. The factory function is not needed.
    return (Model) => {

        return class extends Model {

            $beforeInsert(context) {

                const maybePromise = super.$beforeInsert(context);

                return Promise.resolve(maybePromise).then(() => {
                    // hash the password
                    return this.generateHash();
                });
            }

            $beforeUpdate(opt, context) {

                const maybePromise = super.$beforeUpdate(context);

                return Promise.resolve(maybePromise).then(() => {
                    // hash the password
                    return this.generateHash();
                });
            }

            /**
             * Compares a password to a Bcrypt hash
             * @param  {[type]} password [description]
             * @return {[type]}          [description]
             */
            verifyPassword(password) {
                return Bcrypt.compare(password, this[options.passwordField]);
            }

            /**
             * Generates a Bcrypt hash
             * @param  {String}  password         the password...
             * @param  {Number}  rounds           the number of rounds to use when hashing (default = 12)
             * @return {String}                   returns the hash or null
             */
            generateHash() {

                const password = this[options.passwordField];

                if (password) {

                    if (this.constructor.isBcryptHash(password)) {
                        throw new Error('bcrypt tried to hash another bcrypt hash');
                    }

                    return Bcrypt.hash(password, options.rounds).then((hash) => {
                        this[options.passwordField] = hash;
                    });
                }

                // throw an error if empty passwords aren't allowed
                if (!options.allowEmptyPassword) {
                    throw new Error('password must not be empty');
                }

                return Promise.resolve();
            }


            /**
             * Detect rehashing for avoiding undesired effects
             * @param {String} str A string to be checked
             * @return {Boolean} True if the str seems to be a bcrypt hash
             */
            static isBcryptHash(str) {

                const protocol = str.split('$');

                // Ex $2a$12$K2CtDP7zSGOKgjXjxD9SYey9mSZ9Udio9C95K6wCKZewSP9oBWyPO
                return protocol.length === 4 &&
                    protocol[0] === '' &&
                    ['2a', '2b', '2y'].indexOf(protocol[1]) > -1 &&
                    /^\d+$/.test(protocol[2]) &&
                    protocol[3].length === 53;
            }
        };

    };
};
