/*!
 * Copyright (c) 2020-2023 Digital Bazaar, Inc. All rights reserved.
 */
import {InvalidRequest} from '@interop/oauth2-errors';

class ClientMetadata {
  constructor(meta = {}) {
    this.meta = meta;
  }

  validateNew() {
    try {
      if(!this.meta.redirect_uris && this.redirectUriRequired()) {
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
    const responseTypes = this.meta.response_types;

    return !!(responseTypes &&
      responseTypes.length === 1 &&
      responseTypes[0] === 'id_token token');
  }

  redirectUriRequired() {
    // client_credentials grant type does not need redirect_uris
    return false;
  }
}

export default ClientMetadata;
