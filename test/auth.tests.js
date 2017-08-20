const assert = require('assert');
const sinon = require('sinon');
const $require = require('proxyquire').noPreserveCache();

let mockedServer;
let openerMock = sinon.stub();

describe('auth', () => {
  it('shuold export a function', () => {
    const Auth = require('../src/auth');
    assert.equal(typeof Auth, 'function')
  });

  describe('configuration', () => {
    const Auth = $require('../src/auth', {
      './server': function(){
        return mockedServer
      },
      'opener': openerMock
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
  })

  describe('setClient', () => {
    const Auth = $require('../src/auth', {
      './server': function(){
        return mockedServer
      }
    });

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

  describe('_performAuthenticateRequest', () => {
    const Auth = $require('../src/auth', {
      './server': function(){
        return mockedServer
      },
      'opener': openerMock
    });

    describe('when server fails to start', () => {
      let err, res;
      before((done) => {
        let mockedEvent;
        mockedEvent = {
          on: sinon.stub().returns({ on: sinon.stub().returns({ on : sinon.stub()})})
        };
        mockedServer = {
          createServer: sinon.stub().returns(mockedEvent).yields(new Error('there was an error')),
        };

        (new Auth())._performAuthenticateRequest({}, (e, r) => {
          err = e;
          res = r;
          done();
        });
      });

      it('should return error', () => {
        assert.equal(err.message, 'there was an error');
        assert.equal(res, undefined);
      })
    });

    describe('when server is created successfully', () => {
      let err, res, loadedOn, responseOn, errorOn;
      before(() => {
        errorOn = { on : sinon.stub()};
        responseOn = { on: sinon.stub().returns(errorOn)};
        loadedOn = {
          on: sinon.stub().returns(responseOn)
        };
        mockedServer = {
          createServer: sinon.stub().returns(loadedOn),
          destroy: sinon.stub()
        };

        (new Auth())
          .setAuthorizationServer({
            authorization_endpoint: 'http://as.com/authorize'
          })
          .setClient({
            client_id: '123'
          })
          ._performAuthenticateRequest({}, (e, r) => {
            err = e;
            res = r;
          });
      });

      it('should regiter corresponding events', () => {
        assert.equal(errorOn.on.args[0][0], 'error');
        assert.equal(responseOn.on.args[0][0], 'response');
        assert.equal(loadedOn.on.args[0][0], 'loaded');
      })

      describe('when loaded event is emited by server', () => {
        before(() => {
          loadedOn.on.args[0][1]();
        });

        it('should call opener with url', () => {
          assert.ok(openerMock.args[0][0].indexOf('http://as.com/authorize?redirect_uri=https%3A%2F%2F127.0.0.1%3A8000%2F&client_id=123&response_type=code&state=') === 0)
        })
      });

      describe('when error event is emitted by server', () => {
        before(() => {
          errorOn.on.args[0][1]('error');
        });

        it('should call authenticate callback with error', () => {
          assert.equal(err, 'error');
          assert.ok(mockedServer.destroy.called);          
        });
      });

      describe('when response event is emitted by server', () => {
        before(() => {
          responseOn.on.args[0][1]({ foo: 'bar' });
        })

        it('should call authenticate callback with response', () => {
          assert.equal(res.foo, 'bar');
          assert.ok(mockedServer.destroy.called);
        });
      });
    })
  });

  describe('authenticate', () => {
    describe('when client_id not set', () => {
      const Auth = $require('../src/auth', {
        './server': function(){
          return mockedServer
        }
      });

      let err, res;
      before((done) => {
        (new Auth())
          .authenticate(null, (e, r) => {
            err = e;
            res = r;
            done();
          });
      });

      it('should return an error', () => {
        assert.equal(err.message, 'client_id cannot be null');
        assert.equal(res, undefined)
      })
    });

    describe('when discovery url is set', () => { 
      const discovery_url = 'http://as.com/.well-known/openid-configuration';
      describe('when the AS is not configured', () => {
        describe('when discovery endpoint has all the information', () => {
          describe('when server returns success', () => {
            let err, res, requestStub, errorOn, responseOn, loadedOn;
            before((done) => {
              requestStub = sinon.stub().onFirstCall().yields(null, { statusCode: 200 }, JSON.stringify({ 
                authorization_endpoint: 'http://as.com/authenticate',
                token_endpoint: 'http://as.com/oauth/token',
                userinfo_endpoint: 'http://as.com/userinfo',
                revocation_endpoint: 'http://as.com/oauth/revoke'
              })).onSecondCall().yields(null, { statusCode: 200 }, JSON.stringify({
                access_token: '456'
              }));
  
              errorOn = { on : sinon.stub()};
              responseOn = { on: sinon.stub().returns(errorOn)};
              loadedOn = {
                on: sinon.stub().returns(responseOn)
              };
              mockedServer = {
                createServer: sinon.stub().returns(loadedOn),
                destroy: sinon.stub()
              };
  
              const Auth = $require('../src/auth', {
                './server': function(){
                  return mockedServer
                },
                'request': requestStub
              });
              (new Auth())
                .setDiscoveryUrl(discovery_url)
                .setClient({
                  redirect_uri: 'http://localhost:8000',
                  client_id : '123'
                })
                .authenticate({ response_mode: 'query' }, (e, r) => {
                  err = e;
                  res = r;
                  done();
                });
              responseOn.on.args[0][1]({ code: '123' });              
            });
  
            it('should return the success response', () => {
              assert.equal(err, null);
              const respones = {
                access_token: '456'
              };
              assert.deepEqual(res, respones)
            });
          });
          
          describe('when server returns error', () => {
            let err, res, requestStub, errorOn, responseOn, loadedOn;
            before((done) => {
              requestStub = sinon.stub().onFirstCall().yields(null, { statusCode: 200 }, JSON.stringify({ 
                authorization_endpoint: 'http://as.com/authenticate',
                token_endpoint: 'http://as.com/oauth/token',
                userinfo_endpoint: 'http://as.com/userinfo',
                revocation_endpoint: 'http://as.com/oauth/revoke'
              }));
  
              errorOn = { on : sinon.stub()};
              responseOn = { on: sinon.stub().returns(errorOn)};
              loadedOn = {
                on: sinon.stub().returns(responseOn)
              };
              mockedServer = {
                createServer: sinon.stub().returns(loadedOn),
                destroy: sinon.stub()
              };
  
              const Auth = $require('../src/auth', {
                './server': function(){
                  return mockedServer
                },
                'request': requestStub
              });
              (new Auth())
                .setDiscoveryUrl(discovery_url)
                .setClient({
                  redirect_uri: 'http://localhost:8000',
                  client_id : '123'
                })
                .authenticate({ }, (e, r) => {
                  err = e;
                  res = r;
                  done();
                });
  
              errorOn.on.args[0][1](new Error('there was an error'));              
            });
  
            it('should return the error response', () => {
              assert.equal(err.message, 'there was an error');
              assert.equal(res, undefined)
            });
          });
        });
        
        describe('when discovery url does not have all the information', () => {
          let err, res, requestStub;
          before((done) => {
            requestStub = sinon.stub().onFirstCall().yields(null, { statusCode: 200 }, JSON.stringify({ 
              authorization_endpoint: 'http://as.com/authenticate'
            }));

            const Auth = $require('../src/auth', {
              './server': function(){
                return mockedServer
              },
              'request': requestStub
            });
            (new Auth())
              .setDiscoveryUrl(discovery_url)
              .setClient({
                redirect_uri: 'http://localhost:8000',
                client_id : '123'
              })
              .authenticate({ }, (e, r) => {
                err = e;
                res = r;
                done();
              });
          });

          it('should return error', () => {
            assert.equal(err.message, 'token_endpoint cannot be null');
            assert.equal(res, undefined);
          });
        });
        
        describe('whem discovery url returns error', () => {
          let err, res, requestStub;
          before((done) => {
            requestStub = sinon.stub().onFirstCall().yields(null, { statusCode: 400 });

            const Auth = $require('../src/auth', {
              './server': function(){
                return mockedServer
              },
              'request': requestStub
            });
            (new Auth())
              .setDiscoveryUrl(discovery_url)
              .setClient({
                redirect_uri: 'http://localhost:8000',
                client_id : '123'
              })
              .authenticate({ }, (e, r) => {
                err = e;
                res = r;
                done();
              });
          });

          it('should return error', () => {
            assert.equal(err.message, 'Unable to load AS settings');
            assert.equal(res, undefined);
          });
        });

        describe('when discovery url does not return a json', () => {
          let err, res, requestStub;
          before((done) => {
            requestStub = sinon.stub().onFirstCall().yields(null, { statusCode: 200 }, 'not-a-json');

            const Auth = $require('../src/auth', {
              './server': function(){
                return mockedServer
              },
              'request': requestStub
            });
            (new Auth())
              .setDiscoveryUrl(discovery_url)
              .setClient({
                redirect_uri: 'http://localhost:8000',
                client_id : '123'
              })
              .authenticate({ refresh_token:  'rt'}, (e, r) => {
                err = e;
                res = r;
                done();
              });
          });

          it('should return error', () => {
            assert.equal(err.message, 'there was an error parsing the response');
            assert.equal(res, undefined);
          });
        });
      });
    });

    describe('when discovery url is not set', () => { 
      describe('when the authorization_endpoint is not configured', () => {
        let err, res;
        before((done) => {
          const Auth = $require('../src/auth', {
            './server': function(){
              return mockedServer
            }
          });
          (new Auth())
            .setClient({
              redirect_uri: 'http://localhost:8000',
              client_id : '123'
            })
            .performRefreshTokenExchange({ refresh_token:  'rt'}, (e, r) => {
              err = e;
              res = r;
              done();
            });
        });

        it('it should return error', () => {
          assert.equal(err.message, 'authorization_endpoint cannot be null');
          assert.equal(res, undefined);
        })
      })

      describe('when the token_endpoint is not configured', () => {
        let err, res;
        before((done) => {
          const Auth = $require('../src/auth', {
            './server': function(){
              return mockedServer
            }
          });
          (new Auth())
            .setAuthorizationServer({
              authorization_endpoint: 'http://as.com/authenticate'
            })
            .setClient({
              redirect_uri: 'http://localhost:8000',
              client_id : '123'
            })
            .performRefreshTokenExchange({ refresh_token:  'rt'}, (e, r) => {
              err = e;
              res = r;
              done();
            });
        });

        it('it should return error', () => {
          assert.equal(err.message, 'token_endpoint cannot be null');
          assert.equal(res, undefined);
        })
      })

      describe('when the AS is configured', () => {
        let err, res, requestStub;
        before((done) => {
          requestStub = sinon.stub().onFirstCall().yields(null, { statusCode: 200 }, JSON.stringify({
            access_token: '123'
          })).onSecondCall().throws();
          const Auth = $require('../src/auth', {
            './server': function(){
              return mockedServer
            },
            'request': requestStub
          });
          (new Auth())
            .setAuthorizationServer({
              authorization_endpoint: 'http://as.com/authenticate',
              token_endpoint: 'http://as.com/oauth/token'
            })
            .setClient({
              redirect_uri: 'http://localhost:8000',
              client_id : '123'
            })
            .performRefreshTokenExchange({ refresh_token:  'rt'}, (e, r) => {
              err = e;
              res = r;
              done();
            });
        });

        it('should call revoke endpoint', () => {
          const tokenRequest = requestStub.args[0];
          assert.equal(tokenRequest[0].url, 'http://as.com/oauth/token');            
          assert.equal(tokenRequest[0].method, 'POST');
          assert.equal(tokenRequest[0].dataType, 'json');
          assert.deepEqual(tokenRequest[0].headers, { 'content-type': 'application/x-www-form-urlencoded' });
          const form = {
            grant_type: 'refresh_token',
            redirect_uri: 'http://localhost:8000',
            client_id: '123',
            refresh_token: 'rt'
          }
          assert.deepEqual(tokenRequest[0].form, form);
        });

        it('should return the success response', () => {
          assert.equal(err, null);
          const respones = {
            access_token: '123'
          };
          assert.deepEqual(res, respones)
        });
      });
    });
  });

  describe('performRefreshTokenExchange', () => {
    describe('when discovery url is set', () => { 
      const discovery_url = 'http://as.com/.well-known/openid-configuration';
      describe('when the AS is not configured', () => {
        describe('when discovery endpoint has all the information', () => {
          let err, res, requestStub;
          before((done) => {
            requestStub = sinon.stub().onFirstCall().yields(null, { statusCode: 200 }, JSON.stringify({ 
              authorization_endpoint: 'http://as.com/authenticate',
              token_endpoint: 'http://as.com/oauth/token',
              userinfo_endpoint: 'http://as.com/userinfo',
              revocation_endpoint: 'http://as.com/oauth/revoke'
            })).onSecondCall().yields(null, { statusCode: 200 }, JSON.stringify({
              access_token: '123'
            }));
            const Auth = $require('../src/auth', {
              './server': function(){
                return mockedServer
              },
              'request': requestStub
            });
            (new Auth())
              .setDiscoveryUrl(discovery_url)
              .setClient({
                redirect_uri: 'http://localhost:8000',
                client_id : '123'
              })
              .performRefreshTokenExchange({ refresh_token:  'rt'}, (e, r) => {
                err = e;
                res = r;
                done();
              });
          });

          it('should call revoke endpoint', () => {
            const discoveryRequest = requestStub.args[0];
            assert.equal(discoveryRequest[0].url, discovery_url);
            assert.equal(discoveryRequest[0].method, 'GET');
            assert.deepEqual(discoveryRequest[0].headers, { 'content-type': 'application/json' });
            const tokenRequest = requestStub.args[1];
            assert.equal(tokenRequest[0].url, 'http://as.com/oauth/token');            
            assert.equal(tokenRequest[0].method, 'POST');
            assert.equal(tokenRequest[0].dataType, 'json');
            assert.deepEqual(tokenRequest[0].headers, { 'content-type': 'application/x-www-form-urlencoded' });
            const form = {
              grant_type: 'refresh_token',
              redirect_uri: 'http://localhost:8000',
              client_id: '123',
              refresh_token: 'rt'
            }
            assert.deepEqual(tokenRequest[0].form, form);
          });

          it('should return the success response', () => {
            assert.equal(err, null);
            const respones = {
              access_token: '123'
            };
            assert.deepEqual(res, respones)
          });
        });
        
        describe('when discovery url does not have all the information', () => {
          let err, res, requestStub;
          before((done) => {
            requestStub = sinon.stub().onFirstCall().yields(null, { statusCode: 200 }, JSON.stringify({ 
              authorization_endpoint: 'http://as.com/authenticate'
            }));

            const Auth = $require('../src/auth', {
              './server': function(){
                return mockedServer
              },
              'request': requestStub
            });
            (new Auth())
              .setDiscoveryUrl(discovery_url)
              .setClient({
                redirect_uri: 'http://localhost:8000',
                client_id : '123'
              })
              .performRefreshTokenExchange({ refresh_token:  'rt'}, (e, r) => {
                err = e;
                res = r;
                done();
              });
          });

          it('should return error', () => {
            assert.equal(err.message, 'token_endpoint cannot be null');
            assert.equal(res, undefined);
          });
        });
        
        describe('whem discovery url returns error', () => {
          let err, res, requestStub;
          before((done) => {
            requestStub = sinon.stub().onFirstCall().yields(null, { statusCode: 400 });

            const Auth = $require('../src/auth', {
              './server': function(){
                return mockedServer
              },
              'request': requestStub
            });
            (new Auth())
              .setDiscoveryUrl(discovery_url)
              .setClient({
                redirect_uri: 'http://localhost:8000',
                client_id : '123'
              })
              .performRefreshTokenExchange({ refresh_token:  'rt'}, (e, r) => {
                err = e;
                res = r;
                done();
              });
          });

          it('should return error', () => {
            assert.equal(err.message, 'Unable to load AS settings');
            assert.equal(res, undefined);
          });
        });

        describe('when discovery url does not return a json', () => {
          let err, res, requestStub;
          before((done) => {
            requestStub = sinon.stub().onFirstCall().yields(null, { statusCode: 200 }, 'not-a-json');

            const Auth = $require('../src/auth', {
              './server': function(){
                return mockedServer
              },
              'request': requestStub
            });
            (new Auth())
              .setDiscoveryUrl(discovery_url)
              .setClient({
                redirect_uri: 'http://localhost:8000',
                client_id : '123'
              })
              .performRefreshTokenExchange({ refresh_token:  'rt'}, (e, r) => {
                err = e;
                res = r;
                done();
              });
          });

          it('should return error', () => {
            assert.equal(err.message, 'there was an error parsing the response');
            assert.equal(res, undefined);
          });
        });
      });

      describe('when the AS is configured', () => {
        let err, res, requestStub;
        before((done) => {
          requestStub = sinon.stub().onFirstCall().yields(null, { statusCode: 200 }, JSON.stringify({
            access_token: '123'
          })).onSecondCall().throws();
          const Auth = $require('../src/auth', {
            './server': function(){
              return mockedServer
            },
            'request': requestStub
          });
          (new Auth())
            .setDiscoveryUrl(discovery_url)
            .setAuthorizationServer({
              authorization_endpoint: 'http://as.com/authenticate',
              token_endpoint: 'http://as.com/oauth/token',
              userinfo_endpoint: 'http://as.com/userinfo'
            })
            .setClient({
              redirect_uri: 'http://localhost:8000',
              client_id : '123'
            })
            .performRefreshTokenExchange({ refresh_token:  'rt'}, (e, r) => {
              err = e;
              res = r;
              done();
            });
        });

        it('should call revoke endpoint', () => {
          const tokenRequest = requestStub.args[0];
          assert.equal(tokenRequest[0].url, 'http://as.com/oauth/token');            
          assert.equal(tokenRequest[0].method, 'POST');
          assert.equal(tokenRequest[0].dataType, 'json');
          assert.deepEqual(tokenRequest[0].headers, { 'content-type': 'application/x-www-form-urlencoded' });
          const form = {
            grant_type: 'refresh_token',
            redirect_uri: 'http://localhost:8000',
            client_id: '123',
            refresh_token: 'rt'
          }
          assert.deepEqual(tokenRequest[0].form, form);
        });

        it('should return the success response', () => {
          assert.equal(err, null);
          const respones = {
            access_token: '123'
          };
          assert.deepEqual(res, respones)
        });
      });
    });

    describe('when discovery url is not set', () => { 
      describe('when the authorization_endpoint is not configured', () => {
        let err, res;
        before((done) => {
          const Auth = $require('../src/auth', {
            './server': function(){
              return mockedServer
            }
          });
          (new Auth())
            .setClient({
              redirect_uri: 'http://localhost:8000',
              client_id : '123'
            })
            .performRefreshTokenExchange({ refresh_token:  'rt'}, (e, r) => {
              err = e;
              res = r;
              done();
            });
        });

        it('it should return error', () => {
          assert.equal(err.message, 'authorization_endpoint cannot be null');
          assert.equal(res, undefined);
        })
      })

      describe('when the token_endpoint is not configured', () => {
        let err, res;
        before((done) => {
          const Auth = $require('../src/auth', {
            './server': function(){
              return mockedServer
            }
          });
          (new Auth())
            .setAuthorizationServer({
              authorization_endpoint: 'http://as.com/authenticate'
            })
            .setClient({
              redirect_uri: 'http://localhost:8000',
              client_id : '123'
            })
            .performRefreshTokenExchange({ refresh_token:  'rt'}, (e, r) => {
              err = e;
              res = r;
              done();
            });
        });

        it('it should return error', () => {
          assert.equal(err.message, 'token_endpoint cannot be null');
          assert.equal(res, undefined);
        })
      })

      describe('when the AS is configured', () => {
        let err, res, requestStub;
        before((done) => {
          requestStub = sinon.stub().onFirstCall().yields(null, { statusCode: 200 }, JSON.stringify({
            access_token: '123'
          })).onSecondCall().throws();
          const Auth = $require('../src/auth', {
            './server': function(){
              return mockedServer
            },
            'request': requestStub
          });
          (new Auth())
            .setAuthorizationServer({
              authorization_endpoint: 'http://as.com/authenticate',
              token_endpoint: 'http://as.com/oauth/token'
            })
            .setClient({
              redirect_uri: 'http://localhost:8000',
              client_id : '123'
            })
            .performRefreshTokenExchange({ refresh_token:  'rt'}, (e, r) => {
              err = e;
              res = r;
              done();
            });
        });

        it('should call revoke endpoint', () => {
          const tokenRequest = requestStub.args[0];
          assert.equal(tokenRequest[0].url, 'http://as.com/oauth/token');            
          assert.equal(tokenRequest[0].method, 'POST');
          assert.equal(tokenRequest[0].dataType, 'json');
          assert.deepEqual(tokenRequest[0].headers, { 'content-type': 'application/x-www-form-urlencoded' });
          const form = {
            grant_type: 'refresh_token',
            redirect_uri: 'http://localhost:8000',
            client_id: '123',
            refresh_token: 'rt'
          }
          assert.deepEqual(tokenRequest[0].form, form);
        });

        it('should return the success response', () => {
          assert.equal(err, null);
          const respones = {
            access_token: '123'
          };
          assert.deepEqual(res, respones)
        });
      });
    });
  });

  describe('revokeRefreshToken', () => {
    describe('when no revoke endpoint is defined', () => {
      const Auth = $require('../src/auth', {
        './server': function(){
          return mockedServer
        }
      });
  
      let err, res;
      before((done) => {
        (new Auth())
          .revokeRefreshToken({ refresh_token: '123', client_id: '123' }, (e, r) => {
            err = e;
            res = r;
            done();
          });
      });

      it('should return error', () => {
        assert.equal(err.message, 'revoke endpoint is not defined');
        assert.equal(res, undefined);
      });
    });

    describe('when revoke endpoint does not exist', () => {
      const requestStub = sinon.stub().yields(null, { statusCode: 400 }, { error: 'there was an error'});
      const Auth = $require('../src/auth', {
        './server': function(){
          return mockedServer
        },
        'request': requestStub
      });
  
      let err, res;
      before((done) => {
        (new Auth())
          .setAuthorizationServer({
            revocation_endpoint: 'http://as.com/oauth/revoke'
          })
          .revokeRefreshToken({ refresh_token: '123', client_id: '123' }, (e, r) => {
            err = e;
            res = r;
            done();
          });
      });
  
      it('should call revoke endpoint', () => {
        const r = requestStub.args[0];
        assert.equal(r[0].url, 'http://as.com/oauth/revoke');
        assert.equal(r[0].method, 'POST');
        assert.equal(r[0].dataType, 'json');
        assert.deepEqual(r[0].headers, { 'content-type': 'application/x-www-form-urlencoded' });
        assert.deepEqual(r[0].form, { token: '123', client_id: '123' });
      });

      it('should return error', () => {
        assert.equal(err.message, 'there was an error revoking token');
        assert.equal(res, undefined);
      });
    });

    describe('when revoke endpoint exists', () => {
      const requestStub = sinon.stub().yields(null, { statusCode: 200 }, { status: 'success'});
      const Auth = $require('../src/auth', {
        './server': function(){
          return mockedServer
        },
        'request': requestStub
      });
  
      let err, res;
      before((done) => {
        (new Auth())
          .setAuthorizationServer({
            revocation_endpoint: 'http://as.com/oauth/revoke'
          })
          .setClient({
            extras: { foo: 'bar' }
          })
          .revokeRefreshToken({ refresh_token: '123', client_id: '123', extras: { baz: 'taz'} }, (e, r) => {
            err = e;
            res = r;
            done();
          });
      });
  
      it('should call revoke endpoint', () => {
        const r = requestStub.args[0];
        assert.equal(r[0].url, 'http://as.com/oauth/revoke');
        assert.equal(r[0].method, 'POST');
        assert.equal(r[0].dataType, 'json');
        assert.deepEqual(r[0].headers, { 'content-type': 'application/x-www-form-urlencoded' });
        assert.deepEqual(r[0].form, { token: '123', client_id: '123', foo: 'bar', baz: 'taz' });
      });
      
      it('should return sucess', () => {
        assert.equal(err, null);
        assert.deepEqual(res, { status: 'success'})
      });
    })
  });

  describe('userInfo', () => {
    describe('when no userinfo endpoint is defined', () => {
      const Auth = $require('../src/auth', {
        './server': function(){
          return mockedServer
        }
      });

      let err, res;
      before((done) => {
        (new Auth())
          .userInfo('at', (e, r) => {
            err = e;
            res = r;
            done();
          });
      });

      it('should return error', () => {
        assert.equal(err.message, 'userinfo endpoint is not defined');
        assert.equal(res, undefined)
      });
    });

    describe('when userinfo does not exist', () => {
      const requestStub = sinon.stub().yields(null, { statusCode: 400 }, { error: 'there was an error'});
      const Auth = $require('../src/auth', {
        './server': function(){
          return mockedServer
        },
        'request': requestStub
      });
  
      let err, res;
      before((done) => {
        (new Auth())
          .setAuthorizationServer({
            userinfo_endpoint: 'http://as.com/userinfo'
          })
          .userInfo('at', (e, r) => {
            err = e;
            res = r;
            done();
          });
      });
  
      it('should call userinfo endpoint', () => {
        const r = requestStub.args[0];
        assert.equal(r[0].url, 'http://as.com/userinfo');
        assert.equal(r[0].method, 'GET');
        assert.deepEqual(r[0].headers, { 'content-type': 'application/json', 'authorization' : 'Bearer at' });
      });
  
      it('should return error', () => {
        assert.equal(err.message, 'there was an error calling userinfo');
        assert.equal(res, undefined)
      });
    })

    describe('when userinfo exists', () => {
      const requestStub = sinon.stub().yields(null, { statusCode: 200 }, { status: 'success'});
      const Auth = $require('../src/auth', {
        './server': function(){
          return mockedServer
        },
        'request': requestStub
      });
  
      let err, res;
      before((done) => {
        (new Auth())
          .setAuthorizationServer({
            userinfo_endpoint: 'http://as.com/userinfo'
          })
          .userInfo('at', (e, r) => {
            err = e;
            res = r;
            done();
          });
      });
  
      it('should call userinfo endpoint', () => {
        const r = requestStub.args[0];
        assert.equal(r[0].url, 'http://as.com/userinfo');
        assert.equal(r[0].method, 'GET');
        assert.deepEqual(r[0].headers, { 'content-type': 'application/json', 'authorization' : 'Bearer at' });
      });
  
      it('should return sucess', () => {
        assert.equal(err, null);
        assert.deepEqual(res, { status: 'success'})
      });
    });
  });
});