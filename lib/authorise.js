'use strict';
module.exports = function* (next){
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
