'use strict';
let crypto = require('crypto');
let model = require('./lib/model');
let grant = require('./lib/grant');
let authorise = require('./lib/authorise');
module.exports = OAuth2Server;

function OAuth2Server (config) {

  if (!(this instanceof OAuth2Server)) return new OAuth2Server(config);

  config = config || {};

  this.model = model;


  this.accessTokenLifetime = config.accessTokenLifetime !== undefined ?
    config.accessTokenLifetime : 3600;
}
OAuth2Server.authorise = authorise;

OAuth2Server.grant = grant;
