/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';
const {generateId} = require('bnid');
const {snakeCase} = require('snake-case');
const {
  InvalidRequest, AccessDenied
} = require('@interop/oauth2-errors');

const {ClientMetadata} = require('./ClientMetadata');

function handleClientRegistration({authentication, register,
  defaults = {}, allowClientProvidedId = false, logger}) {
  return async (req, res) => {
    try {
      await _authenticate({req, authentication, logger});

      const registration = _parseRegistration({req, defaults});

      const result = registration.validateNew();
      if(!result.valid) {
        throw result.error;
      }

      await _ensureClientId({registration, allowClientProvidedId});
      await _generateClientSecret({registration, defaults});

      // registration.registration_access_token = '...';
      // registration.registration_client_uri = (new URL('/register/' +
      //   encodeURIComponent(registration.client_id), baseUrl)).toString();

      // Epoch time
      registration.client_id_issued_at = Math.floor(Date.now() / 1000);

      const client = await register({registration});

      _response({client, res});
    } catch(error) {
      if(logger) {
        logger.error(error);
      }
      error.respond(res);
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

  const registrationDefaults = {};

  for(const [key, value] of Object.entries(defaults)) {
    registrationDefaults[snakeCase(key)] = value;
  }

  return new ClientMetadata({...registrationDefaults, ...registration});
}

async function _authenticate({req, res, authentication}) {
  if(authentication.strategy === 'bearer') {
    const token = await _extractBearerToken({req, res});
    try {
      await authentication.validateInitialAccessToken({token});
    } catch(e) {
      throw new AccessDenied({
        description: `Invalid authentication code: ${e.message}`
      });
    }

  } else {
    throw new InvalidRequest({
      description: 'Only the Bearer auth scheme is currently supported.'});
  }
}

async function _extractBearerToken({req}) {
  const authorization = req.headers && req.headers.authorization;

  if(!authorization) {
    throw new AccessDenied({description: 'Authentication Code required.'});
  }
  const components = authorization.split(' ');
  const [scheme, token] = components;

  if(scheme !== 'Bearer') {
    throw new InvalidRequest({description: 'Invalid authorization scheme.'});
  }

  if(components.length !== 2) {
    throw new InvalidRequest({description: 'Invalid authorization header.'});
  }

  return token;
}

async function _ensureClientId({registration, allowClientProvidedId}) {
  if(registration.client_id && allowClientProvidedId) {
    return;
  }

  registration.client_id = await generateId();
}

async function _generateClientSecret({registration, defaults}) {
  if(registration.requiresClientSecret()) {
    registration.client_secret = await generateId();
  }
  if(registration.client_secret) {
    registration.client_secret_expires_at = defaults.clientSecretExpiresAt || 0;
  }
}

module.exports = {
  handleClientRegistration,
  ClientMetadata,
  _authenticate,
  _ensureClientId,
  _extractBearerToken,
  _generateClientSecret,
  _parseRegistration,
  _response
};
