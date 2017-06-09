'use strict';

import test from 'ava';

const Bcrypt = require('../index')();
const BcryptWithOptions = require('../index')({ passwordField: 'hash' });
const Knex = require('knex');
const Model = require('objection').Model;

const knex = Knex({
    client: 'sqlite3',
    connection: {
        filename: ':memory:'
    },
    useNullAsDefault: true
});

// bind knex instance to objection
Model.knex(knex);

// objection models
class Dog extends Bcrypt(Model) {
    static get tableName() {
        return 'dog';
    }
}

class Cat extends BcryptWithOptions(Model) {
    static get tableName() {
        return 'cat';
    }
}

// tests
test.before(async (t) => {
    await knex.schema.createTable('dog', (table) => {
        table.increments();
        table.string('name');
        table.string('password');
    });

    await knex.schema.createTable('cat', (table) => {
        table.increments();
        table.string('name');
        table.string('hash');
    });
});


test('hashes and verifies a password', async (t) => {
    const password = 'Turtle123!';
    const dog = await Dog.query().insert({ name: 'JJ', password });
    t.true(await dog.verifyPassword(password));
});


test('creates new hash when updating password', async (t) => {
    const original = 'Turtle123!';
    const updated = 'Monkey69!';

    const dog = await Dog.query().insert({ name: 'JJ', password: original });
    t.true(await dog.verifyPassword(original));

    const updatedDog = await dog.$query().patchAndFetchById(dog.id, { password: updated });
    t.true(await updatedDog.verifyPassword(updated));
});


test('does not hash an empty password', async (t) => {
    const password = '';
    const dog = await Dog.query().insert({ name: 'JJ', password });
    t.falsy(dog.password);
});


test('throws an error when attempting to hash a bcrypt hash', async (t) => {
    const dog = Dog.query().insert({ name: 'JJ', password: '$2a$12$sWSdI13BJ5ipPca/f8KTF.k4eFKsUtobfWdTBoQdj9g9I8JfLmZty' });
    const error = await t.throws(dog);
    t.is(error.message, 'Bcrypt tried to hash another bcrypt hash');
});


test('can override default password field', async (t) => {
    const password = 'Turtle123!';
    const cat = await Cat.query().insert({ name: 'Maude', hash: password });
    t.truthy(cat.hash);
    t.true(await cat.verifyPassword(password));
});
