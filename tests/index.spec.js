/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';
const chai = require('chai');
chai.use(require('chai-http'));
chai.should();
const {expect} = chai;

const express = require('express');
const bodyParserJson = express.json();

const {
  handleClientRegistration
} = require('../lib');

const registerUrl = '/oauth2/register';
const VALID_TOKEN = 'abcd1234';
const INVALID_TOKEN = 'xyz567';

describe('handleClientRegistration', () => {
  const app = express();
  app.post(
    registerUrl,
    bodyParserJson,
    handleClientRegistration({
      baseUrl: 'https://as.example.com',
      authentication: {
        strategy: 'bearer',
        validateInitialAccessToken: async ({token}) => {
          if(token !== VALID_TOKEN) {
            throw new Error('Token not found.');
          }
        }
      },
      // eslint-disable-next-line no-unused-vars
      register: async ({registration, credentials: {initialAccessToken}}) => {
        // save to database, then return the saved client metadata
        return registration;
      }
    })
  );

  let requester;

  before(async () => {
    requester = chai.request(app).keepOpen();
  });

  after(async () => {
    requester.close();
  });

  it('should error if called un-authenticated', async () => {
    const res = await requester.post(registerUrl).send({});
    expect(res).to.have.status(403);
    expect(res).to.be.json;
    expect(res.body.error).to.equal('access_denied');
    expect(res.body.error_description)
      .to.equal('Authentication Code required.');
  });

  it('should error if called with a non-bearer auth scheme', async () => {
    const res = await requester.post(registerUrl)
      .set('Authorization', 'Basic abcd123')
      .send({});
    expect(res).to.have.status(400);
    expect(res).to.be.json;
    expect(res.body.error).to.equal('invalid_request');
    expect(res.body.error_description)
      .to.equal('Invalid authorization scheme.');

  });

  it('should error if given an invalid token', async () => {
    const res = await requester.post(registerUrl)
      .set('Authorization', `Bearer ${INVALID_TOKEN}`)
      .send({});
    expect(res).to.have.status(403);
    expect(res.body.error_description).to
      .equal('Invalid authentication code: Token not found.');
  });

  it('should return a valid registration with correct auth token', async () => {
    const res = await requester.post(registerUrl)
      .set('Authorization', `Bearer ${VALID_TOKEN}`)
      .send({
        client_name: 'Example client.'
      });
    expect(res).to.have.status(201);
    expect(res).to.be.json;
    expect(res.body.grant_types).to.eql(['client_credentials']);
    expect(res.body.client_id).to.be.a('string');
    expect(res.body.client_secret).to.be.a('string');
    expect(res.body.client_id_issued_at).to.be.a('number');
    expect(res.body.client_secret_expires_at).to.equal(0);
    expect(res.body.token_endpoint_auth_method).to.equal('client_secret_post');
    expect(res.body.client_name).to.equal('Example client.');
  });
});
