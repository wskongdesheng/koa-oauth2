'use strict';
let crypto = require('crypto');
let model = require('./lib/model');
module.exports = OAuth2Server;
function OAuth2Server (){
  if (!(this instanceof OAuth2Server)) return new OAuth2Server();
  this.model = model;
}
function generateRandomToken() {
  let buffer = crypto.randomBytes(256);
  let token = crypto.createHash('sha1').update(buffer).digest('hex');
  return token;
};

function* grant(){
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
  let authedClient = yield model.getClient(client.cliendId, client.clientSecret);
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

function* Authorise (){
  let bearerToken = getBearerToken();
  yield checkToken(bearerToken);
};

function getBearerToken (){
  let headerToken = this.request.header.Authorization,
    token = this.params.access_token;
  let methodsUsed = (headerToken !== undefined) + (token !== undefined);
  if(methodsUsed > 1){
    this.body = "Only one method may be used to authenticate at a time";
    return;
  }else if (methodsUsed === 0){
    this.body = "The access token was not found";
    return;
  }

  if (headerToken) {
    var matches = headerToken.match(/Bearer\s(\S+)/);

    if (!matches) {
      this.body = "Malformed auth header";
      return;
    }

    headerToken = matches[1];
  }
  this.bearerToken = headerToken || token;
  return this.beaerToken;
};

function* checkToken(bearerToken){
  let token = model.getAccessToken(bearerToken);
  if(!token){
    this.body = "The access token provided is invalid.";
    return;
  }

  if (token.expires !== null &&
      (!token.expires || token.expires < new Date())) {
    this.body = "The access token provided has expired.";
    return;
  }
  this.params.oauth = { bearerToken: token };
};
