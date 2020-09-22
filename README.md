# Bedrock OAuth2 Dynamic Client Registration _(oauth2-client-registration-handler)_

[![Node.js CI](https://github.com/digitalbazaar/oauth2-client-registration-handler/workflows/Node.js%20CI/badge.svg)](https://github.com/digitalbazaar/oauth2-client-registration-handler/actions?query=workflow%3A%22Node.js+CI%22)

> OAuth2 Dynamic Registration handler for custom authorization servers.

## Table of Contents

- [Background](#background)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Background

Constraints/Limitations:

* Only supporting `client_credentials` grant type for now.
* Initial registration authentication method is bearer token.

Relevant specifications:

* [OAuth 2.0 Dynamic Client Registration Protocol](https://tools.ietf.org/html/rfc7591)
* [OAuth 2.0 Dynamic Client Registration Management Protocol](https://tools.ietf.org/html/rfc7592)

## Security

TBD

## Install

- Node.js 12+ is required.

To install locally (for development):

```
git clone https://github.com/digitalbazaar/oauth2-client-registration-handler.git
cd oauth2-client-registration-handler
npm install
```

## Usage

This library exports a route handler to perform OAuth2 Dynamic Client 
Registration that can be added to an existing Bedrock or Express.js application.

```js
const {handleClientRegistration} = require('oauth2-client-registration-handler');

app.post('/oauth2/register',
  handleClientRegistration({
    authentication: {
      strategy: 'bearer',
      validateInitialAccessToken: ({token}) => {/* custom token validation logic */}
    },
    getClient: clientId => {
      // custom 'load client' callback (read registered client from db)
    },
    register: ({body}) => {
      // custom registration callback (saves client to database etc)
    },
    defaults: {
      clientSecretExpiresAt: 0, // never expires
      grantTypes: ['client_credentials'],
      tokenEndpointAuthMethod: 'client_secret_post'
    }
  }))
);
```

## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[New BSD License (3-clause)](LICENSE) © Digital Bazaar
