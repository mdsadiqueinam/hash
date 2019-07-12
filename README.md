<div align="center">
  <img src="https://res.cloudinary.com/adonisjs/image/upload/q_100/v1557762307/poppinss_iftxlt.jpg" width="600px">
</div>

# Password hashing
> Module to hash values with support for [PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md)

[![circleci-image]][circleci-url] [![npm-image]][npm-url] ![][typescript-image] [![license-image]][license-url]

This module is used by [AdonisJs](https://adonisjs.com) to hash user password with first class support for upgrading logic. A big thanks to the author of [uphash](https://github.com/simonepri/upash), who inspired me to use [PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md). I would have used uphash directly, but the user facing API is different from what I desire.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
## Table of contents

- [Features](#features)
- [Usage](#usage)
- [Switching drivers](#switching-drivers)
- [Adding custom drivers](#adding-custom-drivers)
- [API Docs](#api-docs)
- [Maintainers](#maintainers)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Features
1. Support for multiple hashing algorithms.
2. Option to extend and add your own hashing algorithms.
3. Wraps the hash output to a [PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md), this allows upgrading user passwords, when the underlying configuration changes.

## Usage
Install the package from npm registry as follows:

```sh
npm i @poppinss/hash

# yarn
yarn add @poppinss/hash
```

and then use it as follows:

```ts
import { Hash } from '@poppinss/hash'
const hash = new Hash(iocContainer, config)

const hashedValue = await hash.hash('password')
await hash.verify(hashedValue)

await hash.needsRehash(hashedValue) // false
```

## Switching drivers
You can switch drivers using the `driver` method.

```ts
import { Hash } from '@poppinss/hash'
const hash = new Hash(iocContainer, config)

await hash.driver('bcrypt').hash('password')
```

## Adding custom drivers
The custom drivers can be added using the `extend` method.

```ts
import { Hash, HashDriverContract } from '@poppinss/hash'
const hash = new Hash(iocContainer, config)

class Scrypt implements HashDriverContract {}

hash.extend('scrypt', (container) => {
  return new Scrypt()
})
```

## API Docs
Following are the autogenerated files via Typedoc

* [API](docs/README.md)

## Maintainers
[Harminder virk](https://github.com/thetutlage)

[circleci-image]: https://img.shields.io/circleci/project/github/poppinss/hash/master.svg?style=for-the-badge&logo=circleci
[circleci-url]: https://circleci.com/gh/poppinss/hash "circleci"

[npm-image]: https://img.shields.io/npm/v/@poppinss/hash.svg?style=for-the-badge&logo=npm
[npm-url]: https://npmjs.org/package/@poppinss/hash "npm"

[typescript-image]: https://img.shields.io/badge/Typescript-294E80.svg?style=for-the-badge&logo=typescript

[license-url]: LICENSE.md
[license-image]: https://img.shields.io/aur/license/pac.svg?style=for-the-badge
