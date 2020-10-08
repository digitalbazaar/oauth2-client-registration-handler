/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';
const {generateId} = require('bnid');
const {snakeCase} = require('snake-case');
const {
  InvalidRequest, AccessDenied
} = require('@interop/oauth2-errors');

const {ClientMetadata, FORBIDDEN_FIELDS} = require('./ClientMetadata');

function handleClientRegistration({
  authentication, register, defaults = {}, allowClientProvidedId = false,
  logger
}) {
  return async (req, res) => {
    try {
      const initialAccessToken = await _authenticate({
        req, authentication, logger});

      const {body: registrationBody} = req;

      const registration = _parseRegistration({registrationBody, defaults});

      const result = registration.validateNew();
      if(!result.valid) {
        throw result.error;
      }

      // client can be optionally overriden by the register() callback
      await _ensureClientId({registration, allowClientProvidedId});
      await _generateClientSecret({registration, defaults});

      // Epoch time
      registration.client_id_issued_at = Math.floor(Date.now() / 1000);

      let client;
      try {
        client = await register({
          registration, credentials: {initialAccessToken}
        });
      } catch(e) {
        throw new InvalidRequest({
          description: `Error registering client: "${e.message}".`
        });
      }

      return _respond({client, res});
    } catch(error) {
      if(logger) {
        logger.error(error);
      }
      error.respond(res);
    }
  };
}

function _respond({client, res}) {
  res.set({
    'Cache-Control': 'no-store',
    Pragma: 'no-cache'
  });

  res.status(201).json(client);
}

function _parseRegistration({registrationBody, defaults}) {
  if(!registrationBody) {
    throw new InvalidRequest({
      description: 'Missing registration request body.'
    });
  }

  const hit = FORBIDDEN_FIELDS.find(prop =>
    registrationBody[prop] !== undefined);
  if(hit) {
    throw new InvalidRequest({
      description: `Registration MUST NOT include the ${hit} field.`
    });
  }

  const registrationDefaults = {};

  for(const [key, value] of Object.entries(defaults)) {
    registrationDefaults[snakeCase(key)] = value;
  }

  return new ClientMetadata({...registrationDefaults, ...registrationBody});
}

async function _authenticate({req, res, authentication}) {
  let token;

  if(authentication.strategy === 'bearer') {
    token = await _extractBearerToken({req, res});
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
  return token;
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
  _respond
};
