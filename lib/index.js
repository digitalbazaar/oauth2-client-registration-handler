/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';
const {generateId} = require('bnid');
const {snakeCase} = require('snake-case');
const authorization = require('auth-header');
const {
  InvalidRequest, AccessDenied
} = require('@interop/oauth2-errors');

const {ClientMetadata, FORBIDDEN_FIELDS} = require('./ClientMetadata');

/**
 * Returns an Express.js/Bedrock middleware function that handles OAuth 2.0
 * Dynamic Client Registration.
 *
 * @see https://tools.ietf.org/html/rfc7591
 *
 * @param {object} options - Options hashmap.
 * @param {object} options.authentication - Authentication strategy config,
 *   including the endpoint authn strategy, and the validate initial token
 *   callback. For example,
 *   `{strategy: 'bearer', validateInitialAccessToken}`.
 * @param {Function} options.register - Registration callback with the signature
 *   `({registration, credentials: {initialAccessToken}})`, where the
 *   client registration is typically persisted in a database.
 * @param {object} [options.defaults={}] - Hashmap of default registration
 *   values.
 * @param {boolean} [options.allowClientProvidedId=false] - Whether to allow
 *   clients to provide their own `client_id` values in the registration.
 * @param {object} options.logger - Logger.
 *
 * @returns {Function} Returns middleware request handler.
 */
function clientRegistrationHandler({
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
          description: `Error in register() callback: "${e.message}".`
        });
      }

      return _respond({client, res});
    } catch(error) {
      _error({error, logger, res});
    }
  };
}

function _error({error, logger, res}) {
  if(logger) {
    logger.error('Dynamic client registration error.', {error});
  }
  const {
    error: errorId, error_description: description, error_uri: uri
  } = error;

  const statusCode = error.statusCode || 400;
  const oauth2ErrorResponse = {
    error: errorId || 'invalid_request',
    error_description: description || error.message,
    error_uri: uri
  };
  res.set({
    'Cache-Control': 'no-store',
    Pragma: 'no-cache'
  });
  return res.status(statusCode).json(oauth2ErrorResponse);
}

function _respond({client, res}) {
  res.set({
    'Cache-Control': 'no-store',
    Pragma: 'no-cache'
  });

  res.status(201).json(client);
}

function _parseRegistration({registrationBody, defaults = {}}) {
  if(!registrationBody) {
    throw new InvalidRequest({
      description: 'Missing registration request body.'
    });
  }

  for(const field in registrationBody) {
    if(FORBIDDEN_FIELDS.has(field)) {
      throw new InvalidRequest({
        description: `Registration MUST NOT include the "${field}" field.`
      });
    }
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
  const header = req.get('Authorization');
  if(!header) {
    throw new AccessDenied({description: 'Authentication Code required.'});
  }

  const {scheme, token} = authorization.parse(header);

  if(!(scheme === 'Bearer' && token)) {
    throw new InvalidRequest({description: 'Invalid authorization scheme.'});
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
  clientRegistrationHandler,
  ClientMetadata,
  _authenticate,
  _ensureClientId,
  _extractBearerToken,
  _generateClientSecret,
  _parseRegistration,
  _respond
};
