const assert = require('assert');
const Auth = require('../src/auth');

describe('auth', () => {
  it('shuold export a function', () => {
    assert.equal(typeof Auth, 'function')
  });

  describe('setInternalServer', () => {
    describe('when port is not a number', () => {
      let auth;
      before(() => {
        auth = (new Auth()).setInternalServer({ port : 'asd' })
      });

      it('should configure the server with the default port', () => {
        assert.equal(auth.server_settings.port, 8000);
      });
    });

    describe('when port is a number', () => {
      let auth;
      before(() => {
        auth = (new Auth()).setInternalServer({ port : 8001 })
      });

      it('should configure the server with the default port', () => {
        assert.equal(auth.server_settings.port, 8001);        
      });
    });
  });

  describe('setDiscoveryUrl', () => {
    describe('when called with a valid url', () => {
      let auth;
      before(() => {
        auth = (new Auth());
        auth.as.discovery_url = 'some_url';
        auth.setDiscoveryUrl('some-other-url')
      });

      it('shuold  override existing discovery url', () => {
        assert.equal(auth.as.discovery_url, 'some-other-url');                
      });
    });

    describe('when called without url', () => {
      let auth;
      before(() => {
        auth = (new Auth())
          .setDiscoveryUrl('some-url')
          .setDiscoveryUrl()
      });

      it('shuold not override existing discovery url', () => {
        assert.equal(auth.as.discovery_url, 'some-url');        
      });
    });
  });

  describe('setAuthorizationServer', () => {
    describe('when passed with the correct settings', () => {
      let auth;
      before(() => {
        auth = (new Auth())
          .setAuthorizationServer({
            authorization_endpoint: 'http://as.com/auhtorize',
            token_endpoint: 'http://as.com/oauth/token',
            userinfo_endpoint : 'http://as.com/userinfo',
            revocation_endpoint: 'http://as.com/oauth/revoke'
          })
      });

      it('should set auhtorization server settings', () => {
        assert.equal(auth.as.authorization_endpoint, 'http://as.com/auhtorize');
        assert.equal(auth.as.token_endpoint, 'http://as.com/oauth/token');
        assert.equal(auth.as.userinfo_endpoint, 'http://as.com/userinfo');
        assert.equal(auth.as.revocation_endpoint, 'http://as.com/oauth/revoke');
      });
    });

    describe('when passed without the correct settings', () => {
      let auth;
      before(() => {
        auth = (new Auth())
          .setAuthorizationServer({
            authorization_endpoint: 'http://as.com/auhtorize',
            token_endpoint: 'http://as.com/oauth/token',
            userinfo_endpoint : 'http://as.com/userinfo',
            revocation_endpoint: 'http://as.com/oauth/revoke'
          })
          .setAuthorizationServer({})
          .setAuthorizationServer()
      });

      it('should keep the previous settings', () => {
        assert.equal(auth.as.authorization_endpoint, 'http://as.com/auhtorize');
        assert.equal(auth.as.token_endpoint, 'http://as.com/oauth/token');
        assert.equal(auth.as.userinfo_endpoint, 'http://as.com/userinfo');
        assert.equal(auth.as.revocation_endpoint, 'http://as.com/oauth/revoke');
      });
    });
  });

  describe('setClient', () => {
    describe('when code challenge is not defined', () => {
      let auth;
      before(() => {
        auth = (new Auth())
          .setClient({
            redirect_uri: 'redirect-uri',
            client_id: 'client-id',
            extras: {  foo: 'bar' }
          });
      });

      it('should not set code challenge method', () => {
        assert.equal(auth.client.redirect_uri, 'redirect-uri');
        assert.equal(auth.client.client_id, 'client-id');
        assert.deepEqual(auth.client.extras, {  foo: 'bar' });
        assert.equal(auth.client.code_challenge_method, undefined);        
      });
    });

    describe('when code challenge method exists', () => {
      let auth;
      before(() => {
        auth = (new Auth())
          .setClient({
            redirect_uri: 'redirect-uri',
            client_id: 'client-id',
            extras: {  foo: 'bar' },
            code_challenge_method: 'S256'
          });
      });

      it('should set code challenge method', () => {
        assert.equal(auth.client.redirect_uri, 'redirect-uri');
        assert.equal(auth.client.client_id, 'client-id');
        assert.deepEqual(auth.client.extras, {  foo: 'bar' });
        assert.equal(auth.client.code_challenge_method, 'S256');        
      });
    });

    describe('when code challenge method does not exist', () => {
      let auth;
      before(() => {
        auth = (new Auth())
          .setClient({
            redirect_uri: 'redirect-uri',
            client_id: 'client-id',
            extras: {  foo: 'bar' },
            code_challenge_method: 'not-valid'
          });
      });

      it('should set code challenge method', () => {
        assert.equal(auth.client.redirect_uri, 'redirect-uri');
        assert.equal(auth.client.client_id, 'client-id');
        assert.deepEqual(auth.client.extras, {  foo: 'bar' });
        assert.equal(auth.client.code_challenge_method, undefined);        
      });
    })
  });
});