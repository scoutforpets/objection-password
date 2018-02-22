# Automatic Password Hashing for Objection.js [![Build Status](https://travis-ci.org/scoutforpets/objection-password.svg?branch=master)](https://travis-ci.org/scoutforpets/objection-password)

This plugin automatically adds automatic password hashing to your [Objection.js](https://github.com/Vincit/objection.js/) models. This makes it super-easy to secure passwords and other sensitive data.

Under the hood, the plugin uses [bcrypt](https://en.wikipedia.org/wiki/Bcrypt) for hashing.

## Installation

### NPM
`npm i objection-password`

### Yarn
`yarn add objection-password`

## Usage

### Hashing your data

```js
// import the plugin
const Password = require('objection-password')();
const Model = require('objection').Model;

// mixin the plugin
class Person extends Password(Model) {
    static get tableName() {
        return 'person';
    }
}

const person = await Person.query().insert({
    email: 'matt@damon.com',
    password: 'q1w2e3r4'
});

console.log(person.password);
// $2a$12$sWSdI13BJ5ipPca/f8KTF.k4eFKsUtobfWdTBoQdj9g9I8JfLmZty
```

### Verifying the data
```js
// the password to verify
const password = 'q1w2e3r4';

// fetch the person by email
const person =
    await Person.query().first().where({ email: 'matt@damon.com'});

// verify the password is correct
const passwordValid = await person.verifyPassword(password);
```

## Options

There are a few options you can pass to customize the way the plugin works.

These options can be added when instantiating the plugin. For example:

```js
// import the plugin
const Password = require('objection-password')({
    passwordField: 'hash'
});
```

#### `allowEmptyPassword` (defaults to `false`)
Allows an empty password to be set.

#### `passwordField` (defaults to `password`)
Allows you to override the name of the field to be hashed.

#### `rounds` (defaults to `12`)
The number of number of bcrypt rounds to use when hashing the data.
