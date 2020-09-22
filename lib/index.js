/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';
const {snakeCase} = require('snake-case');

const DEFAULT_GRANT_TYPES = ['client_credentials'];
const DEFAULT_TOKEN_ENDPOINT_AUTH_METHOD = 'client_secret_post';

const FORBIDDEN = [
  'registration_access_token',
  'registration_client_uri',
  'client_secret',
  'client_secret_expires_at',
  'client_id_issued_at',
];

class ClientMetadata {
  constructor({client_id, client_id_issued_at, response_types, client_name,
    client_secret, client_secret_expires_at, registration_access_token,
    grant_types = DEFAULT_GRANT_TYPES, redirect_uris, application_type,
    contacts, logo_uri, client_uri, policy_uri, tos_uri, jwks_uri, jwks,
    token_endpoint_auth_method = DEFAULT_TOKEN_ENDPOINT_AUTH_METHOD,
    token_endpoint_auth_signing_alg, registration_client_uri
  }) {
    this.client_id = client_id;
    this.client_id_issued_at = client_id_issued_at;
    this.client_secret = client_secret;
    this.client_secret_expires_at = client_secret_expires_at;

    this.redirect_uris = redirect_uris;
    this.response_types = response_types;
    this.grant_types = grant_types;

    this.registration_access_token = registration_access_token;
    this.registration_client_uri = registration_client_uri;
    this.application_type = application_type;
    this.contacts = contacts;
    this.client_name = client_name;
    this.logo_uri = logo_uri;
    this.client_uri = client_uri;
    this.policy_uri = policy_uri;
    this.tos_uri = tos_uri;
    this.jwks_uri = jwks_uri;
    this.jwks = jwks;
    this.token_endpoint_auth_method = token_endpoint_auth_method;
    this.token_endpoint_auth_signing_alg = token_endpoint_auth_signing_alg;
  }

  validateNew() {
    try {
      if(!this.redirect_uris && this.redirectUriRequired()) {
        throw new InvalidRequest({
          error: 'invalid_request',
          error_description: 'Missing redirect_uris parameter.'
        });
      }

      const hit = FORBIDDEN.find((prop) => this[prop] !== undefined);
      if(hit) {
        throw new InvalidRequest(
          `Registration MUST NOT include the ${hit} field.`);
      }
    } catch(error) {
      return {valid: false, error};
    }

    return {valid: true};
  }

  requiresClientSecret() {
    return !this.implicitFlow();
  }

  implicitFlow() {
    const responseTypes = this.response_types;

    return !!(responseTypes &&
      responseTypes.length === 1 &&
      responseTypes[0] === 'id_token token');
  }

  redirectUriRequired() {
    return false;
    // TODO: client_credentials grant type does not need redirect_uris, but
    //  handle other cases too
  }
}

function handleClientRegistration({baseUri, authentication, getClient, register,
  defaults, options: {allowClientProvidedId = false}}) {
  return async (req, res, next) => {
    try {
      await _authenticate({req, res, authentication});

      const registration = _parseRegistration({req, defaults});

      const result = registration.validateNew();
      if(!result.valid) {
        throw result.error;
      }

      await _ensureClientId({registration, allowClientProvidedId});
      await _generateClientSecret({registration, defaults});

      // TODO: only if supported
      registration.registration_access_token = '...';
      registration.registration_client_uri = (new URL('/register/' +
        encodeURIComponent(registration.client_id), baseUri)).toString();

      // Epoch time
      registration.client_id_issued_at = Math.floor(Date.now() / 1000);

      const client = await register({registration});

      _response({client, res});
    } catch(e) {
      next(e);
    }
  };
}

function _response({client, res}) {
  res.set({
    'Cache-Control': 'no-store',
    Pragma: 'no-cache'
  });

  res.status(201).json(client);
}

function _parseRegistration({req, defaults}) {
  const {body: registration} = req;

  if(!registration) {
    throw new InvalidRequest({
      error: 'invalid_request',
      error_description: 'Missing registration request body.'
    });
  }

  return new ClientMetadata({...snakeCase(defaults), ...registration});
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
  if(registration.requiresClientSecret()) {
    registration.client_secret = '...'; // TODO: generate client secret
  }
  if(registration.client_secret) {
    registration.client_secret_expires_at = defaults.clientSecretExpiresAt || 0;
  }
}

module.exports = {
  handleClientRegistration
};
