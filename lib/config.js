/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;

const namespace = 'profile-http';
const cfg = config[namespace] = {};

const basePath = '/profile';
cfg.routes = {
  basePath
};
