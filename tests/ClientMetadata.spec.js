/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';
const chai = require('chai');
chai.should();
const {expect} = chai;

const {
  ClientMetadata,
  DEFAULT_GRANT_TYPES,
  DEFAULT_TOKEN_ENDPOINT_AUTH_METHOD
} = require('../lib/ClientMetadata');

describe('ClientMetadata', () => {
  describe('constructor', () => {
    it('should create an instance with defaults', async () => {
      const cm = new ClientMetadata();

      expect(cm.grant_types).to.eql(DEFAULT_GRANT_TYPES);
      expect(cm.token_endpoint_auth_method)
        .to.eql(DEFAULT_TOKEN_ENDPOINT_AUTH_METHOD);
    });
  });

  describe('validateNew', () => {
    it('new instance should validate', async () => {
      const cm = new ClientMetadata();

      const result = cm.validateNew();
      expect(result.valid).to.be.true;
    });
  });

  describe('implicitFlow', () => {
    it('new instance should not be implicit flow by default', async () => {
      const cm = new ClientMetadata();

      expect(cm.implicitFlow()).to.be.false;
    });
  });

  describe('requiresClientSecret', () => {
    it('new instance should require client secret by default', async () => {
      const cm = new ClientMetadata();

      expect(cm.requiresClientSecret()).to.be.true;
    });
  });
});
