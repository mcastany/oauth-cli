const request = require('request');
const Server = require('./server');
const randomstring = require('randomstring');
const opener = require('opener');
const winston = require('winston');
const crypto = require('crypto');

const GRANT_TYPES = {
  AUTHORIZATION_CODE: 'authorization_code',
  REFRESH_TOKEN: 'refresh_token'
};

const RESPONSE_TYPE_CODE = 'code';

const CODE_CHALLENGES = [ 'plain', 'S256' ];

function Auth(settings){
  this.server_settings = {
    port: 8000
  };

  this.client = {
    redirect_uri: `https://127.0.0.1:${this.server_settings.port}/`,
    response_type: RESPONSE_TYPE_CODE
  };

  this.as = {};
  this.logger = (settings || {}).logger || winston;

  return this;  
}

// START: Configuration
Auth.prototype.setInternalServer = function(settings){
  if (Number.isInteger(settings.port)){
    this.server_settings.port = settings.port;
  }

  this.logger.debug('updated internal server settings', this.server_settings);
  return this;
}

Auth.prototype.setDiscoveryUrl = function(url){
  if (url){
    this.as.discovery_url = url;
    this.logger.debug('configured discovery url', this.as.discovery_url);      
  }

  return this;
}

Auth.prototype.setAuthorizationServer = function(settings){
  this.as.authorization_endpoint = settings.authorization_endpoint;
  this.as.token_endpoint = settings.token_endpoint;
  this.as.userinfo_endpoint = settings.userinfo_endpoint;
  this.as.revocation_endpoint = settings.revocation_endpoint;
  this.logger.debug('configured as settings', this.as);
  return this;
}

Auth.prototype.setClient = function(settings){
  this.client.redirect_uri = settings.redirect_uri;
  this.client.client_id = settings.client_id;
  this.client.extras = settings.extras;

  if (settings.code_challenge_method){
    if (CODE_CHALLENGES.indexOf(settings.code_challenge_method) > -1){
      this.client.code_challenge_method = settings.code_challenge_method;      
    } else {
      this.logger.info('unsupported code challenge - ignored')
    }
  }
  return this;  
}
// END: Configuration

Auth.prototype._loadASSettings = function(cb){
  if (!this.as.discovery_url){
    if (!this.as.authorization_endpoint) { return cb(new Error('authorization_endpoint cannot be null')); }
    if (!this.as.token_endpoint) { return cb(new Error('token_endpoint cannot be null')); }
    
    return cb();
  }
  
  if (this.as.authorization_endpoint && this.as.token_endpoint && this.as.userinfo_endpoint){
    return cb();
  }

  request({ 
    url: this.as.discovery_url,
    method: 'GET',
    headers: { 'content-type': 'application/json', },    
  }, (err, response, body) => {
    if (err || response.statusCode !== 200){
      this.logger.error('there was an error loading authorization server data', err || { statusCode: resp.statusCode, body: body });      
      return cb(new Error('Unable to load AS settings'));
    }

    try{
      body = JSON.parse(body);
      this.as.authorization_endpoint = body.authorization_endpoint || this.as.authorization_endpoint;
      this.as.token_endpoint = body.token_endpoint || this.as.token_endpoint;
      this.as.userinfo_endpoint = body.userinfo_endpoint || this.as.userinfo_endpoint;
      this.as.revocation_endpoint = body.revocation_endpoint || this.as.revocation_endpoint;
      this.logger.debug('loading information from wellknown url', this.as);
    } catch(e){
      this.logger.error('there was an error loading authorization server data', e);      
      return cb(e);
    }

    if (!this.as.authorization_endpoint) { return cb(new Error('authorization_endpoint cannot be null')); }
    if (!this.as.token_endpoint) { return cb(new Error('token_endpoint cannot be null')); }

    cb();
  });
}

Auth.prototype._generateRandomString = function(length){
  length = length || 12;
  const state = randomstring.generate();
  this.logger.debug('generating random string for state', state);
  return state;
}

Auth.prototype._generateCodeChallenge = function(method, cb){
  const code_verifier = this._generateRandomString(64);
  this.client.code_verifier = code_verifier;
  
  if (method === 'plain'){
    return code_verifier;
  }

  const hash = crypto.createHash('sha256');
  hash.update(code_verifier);
  return hash.digest().toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function proccessExtras(qs){
  return function(v){
    for (let extra in v) {
      if (!qs.hasOwnProperty(extra)) {
        qs[extra] = v[extra];
      }
    } 
  }
}

// START: Internal OAuth flows
Auth.prototype._performAuthenticateRequest = function(settings, cb){
  if (!this.server_settings.logger){
    this.server_settings.logger = this.logger;
  }
  
  const server = new Server(this.server_settings);
  server.createServer(settings.response_mode, (err) => {
    if(err) { return cb(err); }    
  })
  .on('loaded', () => {
    let qs = {
      'redirect_uri': this.client.redirect_uri,
      'client_id': this.client.client_id,
      'response_type': this.client.response_type,
      'state': settings.state || this._generateRandomString(),
    };

    if (settings.scope){
      qs.scope = settings.scope;
    }

    if (settings.response_mode){
      qs.response_mode = settings.response_mode;
    }

    if (this.client.code_challenge_method){
      qs.code_challenge = this._generateCodeChallenge();
      qs.code_challenge_method = this.client.code_challenge_method;
    }

    [this.client.extras, settings.extras].forEach(proccessExtras(qs));
    
    let url = `${this.as.authorization_endpoint}?${Object.getOwnPropertyNames(qs).map((v) => { return `${v}=${qs[v]}` }).join('&')}`;
    this.logger.info('starting oauth flow', url)
    
    opener(url);
  })
  .on('response', (response) => {
    cb(null, response);
    server.destroy();    
  }).on('error', (err) => {
    server.destroy();
    cb(err);    
  });      
}

Auth.prototype._performCodeExchange = function(settings, cb){
  const body = {
    grant_type: GRANT_TYPES.AUTHORIZATION_CODE,
    redirect_uri: this.client.redirect_uri,
    client_id: this.client.client_id,
    code: settings.code
  };

  if (this.client.code_verifier){
    body.code_verifier = this.client.code_verifier;
  }

  [this.client.extras, settings.extras].forEach((v) => proccessExtras(body));  

  this._performTokenRequest(body, cb);
}

Auth.prototype._performRefreshTokenExchange = function(settings, cb){
  const body = {
    grant_type: GRANT_TYPES.REFRESH_TOKEN,
    redirect_uri: this.client.redirect_uri,
    client_id: this.client.client_id,
    refresh_token: settings.refresh_token
  };

  [this.client.extras, settings.extras].forEach((v) => proccessExtras(body));  

  this._performTokenRequest(body, cb);
}

Auth.prototype._performTokenRequest = function(form, cb){
  request({
    url: this.as.token_endpoint,
    method: 'POST',
    dataType: 'json',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    form: form
  }, (err, resp, body) =>  {
    if(err || resp.statusCode !== 200) { 
      this.logger.error('Error calling token endpoint', err || { statusCode: resp.statusCode, body: body })
      return cb(err || new Error('there was an error calling token endpoint'));
    }

    try{
      body = JSON.parse(body);
    }
    catch(e){
      return cb(e);
    }
    return cb(null, body);
  });
}
// END: Internal OAuth flows

Auth.prototype.authenticate = function(settings, cb){
  if (!this.client.client_id) { return cb(new Error('client_id cannot be null')); }

  this._loadASSettings((err) => {
    if(err) { return cb(err); }

    this._performAuthenticateRequest(settings, (err, response) => {
      if(err) { return cb(err); }
      
      this._performCodeExchange(response, cb);
    });
  });

  return this;
}

Auth.prototype.performRefreshTokenExchange = function(settings, cb){
  const body = {
    grant_type: GRANT_TYPES.REFRESH_TOKEN,
    redirect_uri: this.client.redirect_uri,
    client_id: this.client.client_id,
    refresh_token: settings.refresh_token
  };

  [this.client.extras, settings.extras].forEach((v) => proccessExtras(body));  

  this._loadASSettings((err) => {
    if (err) { return cb(err); }

    this._performTokenRequest(body, cb);
  });
}

Auth.prototype.revokeRefreshToken = function(settings, cb){
  if(!this.as.revocation_endpoint) { return cb(new Error('revoke endpoint is not defined')); }

  const form = {
    client_id: this.client.client_id,
    token: settings.refresh_token
  };

  [this.client.extras, settings.extras].forEach((v) => proccessExtras(form));  
  
  request({
    url: this.as.revocation_endpoint,
    method: 'POST',
    dataType: 'json',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    form: form
  }, (err, resp, body) =>  {
    if(err || resp.statusCode !== 200) { 
      this.logger.error('Error revoking token', err || { statusCode: resp.statusCode, body: body })
      return cb(err || new Error('there was an error revoking token'));
    }

    return cb(null, body);
  });
}

Auth.prototype.userInfo = function(access_token, cb){
  if(!this.as.userinfo_endpoint) { return cb(new Error('userinfo endpoint is not defined')); }
  
  request({
    url: this.as.userinfo_endpoint,
    method: 'GET',
    headers: { 
      'content-type': 'application/json', 
      'authorization' : `Bearer ${access_token}` 
    }
  }, (err, resp, body) =>  {
    if(err || resp.statusCode !== 200) { 
      this.logger.error('Error calling userinfo', err || { statusCode: resp.statusCode, body: body })
      return cb(err || new Error('there was an error calling userinfo'));
    }

    return cb(null, body);
  });
}

module.exports = Auth;