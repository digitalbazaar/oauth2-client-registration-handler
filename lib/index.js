/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';
const {snakeCase} = require('snake-case');

function handleClientRegistration({baseUri, authentication, getClient, register,
  defaults, options: {allowClientProvidedId = false}}) {
  return async (req, res, next) => {
    try {
      await _authenticate({req, res, authentication});

      const registration = _parseRegistration({req, defaults});

      await _ensureClientId({registration, allowClientProvidedId});
      await _generateClientSecret({registration, defaults});

      _validateRegistration({registration});

      // TODO: only if supported
      registration.registration_access_token = '...';
      registration.registration_client_uri = (new URL('/register/' +
        encodeURIComponent(registration.client_id), baseUri)).toString();

      registration.client_id_issued_at = Math.floor(Date.now() / 1000);

      const client = await register({registration});

      _response({client, res});
    } catch(e) {
      next(e);
    }
  };
};

function _response({client, res}) {
  res.set({
    'Cache-Control': 'no-store',
    Pragma: 'no-cache'
  });

  res.status(201).json(client);
}

function _parseRegistration({req, defaults}) {
  const {body: {registration}} = req;
  if(!registration) {
    throw new OAuth2Error({
      error: 'invalid_request',
      error_description: 'Missing registration request body.'
    });
  }
  return {...snakeCase(defaults), registration};
}

async function _authenticate({req, res, authentication}) {
  if(authentication.strategy === 'bearer') {
    const token = _extractBearerToken({req});
    await authentication.validateInitialAccessToken({token});
  } else {
    throw new Error(
      'Only the bearer token auth strategy is currently supported.');
  }
}

async function _extractBearerToken({req}) {
}

async function _ensureClientId({registration, allowClientProvidedId}) {
  if(registration.client_id && allowClientProvidedId) {
    return;
  }

  registration.client_id = '...'; // TODO: generate client id - uuid style
}

async function _generateClientSecret({registration, defaults}) {
  if(_requiresClientSecret({registration})) {
    registration.client_secret = '...'; // TODO: generate client secret
  }
  if(registration.client_secret) {
    registration.client_secret_expires_at = defaults.clientSecretExpiresAt || 0;
  }
}

function _validateRegistration({registration}) {
  if(!registration.redirect_uris && _redirectUriRequired({registration})) {
    throw new OAuth2Error({
      error: 'invalid_request',
      error_description: 'Missing redirect_uris parameter.'
    });
  }
}

function _requiresClientSecret({registration}) {
  return !_isImplicitFlow({registration});
}

function _isImplicitFlow({registration}) {
  const responseTypes = registration.response_types;

  return !!(responseTypes &&
    responseTypes.length === 1 &&
    responseTypes[0] === 'id_token token');
}

function _redirectUriRequired({registration}) {
  return false;
  // TODO: client_credentials grant type does not need redirect_uris, but handle
  //   other cases
}

module.exports = {
  handleClientRegistration
};
