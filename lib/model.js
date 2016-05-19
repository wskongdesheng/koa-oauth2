'use strict';
var model = module.exports,
  util = require('util'),
  db = app.redis.master;
var keys = {
  token: 'tokens:%s',
  client: 'clients:%s',
  refreshToken: 'refresh_tokens:%s',
  grantTypes: 'clients:%s:grant_types',
  user: 'users:%s'
};

model.getAccessToken = function* (bearerToken) {
  let token = yield db.hgetall(util.format(keys.token, bearerToken));
  if (!token) return null;
  return {
    accessToken: token.accessToken,
    clientId: token.clientId,
    expires: token.expires ? new Date(token.expires) : null,
    userId: token.userId
  };
};

model.getClient = function (clientId, clientSecret, clientType) {
  let client = app.settings.client[clientType];
  if (!client || client.clientSecret !== clientSecret || client.clientSecret !== clientSecret) return null;

  return {
    clientId: client.clientId,
    clientSecret: client.clientSecret
  }
};

model.saveAccessToken = function* (accessToken, clientId, expires) {
  yield db.hmset(util.format(keys.token, accessToken), {
    accessToken: accessToken,
    clientId: clientId,
    expires: expires ? expires.toISOString() : null
  });
};

