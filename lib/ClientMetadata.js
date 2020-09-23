/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {InvalidRequest} = require('@interop/oauth2-errors');

const DEFAULT_GRANT_TYPES = ['client_credentials'];
const DEFAULT_TOKEN_ENDPOINT_AUTH_METHOD = 'client_secret_post';

const FORBIDDEN_FIELDS = [
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
    token_endpoint_auth_signing_alg, registration_client_uri,
    software_id, software_version, ...customFields
  } = {}) {
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
    this.software_id = software_id;
    this.software_version = software_version;
    this.logo_uri = logo_uri;
    this.client_uri = client_uri;
    this.policy_uri = policy_uri;
    this.tos_uri = tos_uri;
    this.jwks_uri = jwks_uri;
    this.jwks = jwks;
    this.token_endpoint_auth_method = token_endpoint_auth_method;
    this.token_endpoint_auth_signing_alg = token_endpoint_auth_signing_alg;

    Object.assign(this, customFields);
  }

  validateNew() {
    try {
      if(!this.redirect_uris && this.redirectUriRequired()) {
        throw new InvalidRequest({
          description: 'Missing redirect_uris parameter.'
        });
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
    // client_credentials grant type does not need redirect_uris
    return false;
  }
}

module.exports = {
  ClientMetadata,
  DEFAULT_GRANT_TYPES,
  DEFAULT_TOKEN_ENDPOINT_AUTH_METHOD,
  FORBIDDEN_FIELDS
};
