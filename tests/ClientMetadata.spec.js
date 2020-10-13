/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';
const chai = require('chai');
chai.should();
const {expect} = chai;

const {ClientMetadata} = require('../lib');

describe('ClientMetadata', () => {
  describe('constructor', () => {
    it('should create an instance with defaults', async () => {
      const client = new ClientMetadata();

      expect(client.meta).to.eql({});
    });
  });

  describe('validateNew', () => {
    it('new instance should validate', async () => {
      const client = new ClientMetadata();

      const result = client.validateNew();
      expect(result.valid).to.be.true;
    });
  });

  describe('implicitFlow', () => {
    it('new instance should not be implicit flow by default', async () => {
      const client = new ClientMetadata();

      expect(client.implicitFlow()).to.be.false;
    });
  });

  describe('requiresClientSecret', () => {
    it('new instance should require client secret by default', async () => {
      const client = new ClientMetadata();

      expect(client.requiresClientSecret()).to.be.true;
    });
  });
});
