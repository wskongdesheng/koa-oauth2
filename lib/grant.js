'use strict';
module.exports = function*(){
  let client = extractCredentials();
  let authedClient = checkClient(client);
  let accessToken = generateRandomToken();
  yield saveAccessToken(accessToken, authedClient);
  let response = {
    token_type: 'bearer',
    access_token: accessToken,
    expires_in: 3600
  };
  this.jsonp = response;
  return;
};

function generateRandomToken() {
  let buffer = crypto.randomBytes(256);
  let token = crypto.createHash('sha1').update(buffer).digest('hex');
  return token;
};

function extractCredentials (){
  if (this.request.method !== 'POST' ||
      !this.req.is('application/x-www-form-urlencoded')) {

    this.body = 'Method must be POST with application/x-www-form-urlencoded encoding';
    return;
  }
  this.grantType = this.params.grant_type;
  if (!this.grantType || this.grantType != 'client_credentials') {
    this.body = 'Invalid or missing grant_type parameter';
    return;
  }
  this.client = {clientId: this.params.client_id, clientSecret: this.params.client_secret};
  if (!this.client.clientId) {
    this.body = 'Invalid or missing client_id parameter';
    return;
  } else if (!this.client.clientSecret) {
    this.body = 'Missing client_secret parameter';
    return;
  }
  return this.client;
};

function* checkClient(client){
  let authedClient = model.getClient(client.cliendId, client.clientSecret);
  if (!authedClient) {
    this.body = 'Client credentials are invalid';
    return;
  }
  return authedClient;
};

function* saveAccessToken(accessToken, authedClient){
  let expires = new Date();
  expires.setSeconds(expires.getSeconds() + 3600);

  yield model.saveAccessToken(accessToken, authedClient.clientId, expires);
};
