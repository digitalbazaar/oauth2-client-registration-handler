/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {asyncHandler} = require('bedrock-express');
const bedrock = require('bedrock');
const {config} = bedrock;

bedrock.events.on('bedrock-express.configure.routes', app => {
  const {routes} = config['profile-http'];
  app.post(
    routes.basePath,
    asyncHandler(async (req, res) => {
    }));
  });
