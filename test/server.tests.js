const assert    = require('assert');
const sinon     = require('sinon');
const $require  = require('proxyquire').noPreserveCache();
const mockedBodyParser = {
  urlencoded: sinon.stub(),
  json: sinon.stub()
};
let mockedExpress;
let mockedEvents = { emit: sinon.stub(), on: sinon.stub()  };
const Server = $require('../src/server', {
  'express': function(){
    return mockedExpress;
  },
  'body-parser': mockedBodyParser,
  events: function(){
    return mockedEvents;
  }
});


describe('server', () => {
  it('should be a function', () => {
    assert.equal(typeof Server, 'function');
  });

  describe('createServer', () => {
    describe('when response mode is query', () => {
      const instance = new Server();    
      before((done) => {
        mockedExpress = {
          get: sinon.stub(),
          listen : sinon.stub()
        };

        instance.createServer('query', done);

        mockedExpress.listen.args[0][1]();
      });

      it('should emit loaded event', () => {
        const event = mockedEvents.emit.args.shift();
        assert.ok(event[0], 'loaded');        
      })

      it('should define spinup a server', () => {
        assert.equal(mockedExpress.listen.args[0][0], 8000)
        assert.equal(typeof mockedExpress.listen.args[0][1], 'function')
      })

      it('define get endpoint', () => {
        assert.equal(mockedExpress.get.args[0][0], '/')
        assert.equal(typeof mockedExpress.get.args[0][1], 'function')
      });

      describe('express handler', () => {
        describe('when called with error', () => {
          let req, res;
          before(() => {
            const handler = mockedExpress.get.args[0][1];
            res = {
              send: sinon.stub()
            };
            req = { 
              query: {
                error : 'There was an error'
              }
            };
            
            handler(req, res);
          });

          it('should send the view', () => {
            assert.equal(res.send.args[0][0], '<p>You can close this tab</p>');
          });

          it('should emit error event', () => {
            const event = mockedEvents.emit.args.shift();            
            assert.ok(event[0], 'error');
            assert.ok(event[1].error, '<p>You can close this tab</p>');
          });
        });

        describe('when caleed with sucess', () => {
          let req, res;
          before(() => {
            const handler = mockedExpress.get.args[0][1];
            res = {
              send: sinon.stub()
            };
            req = { 
              query: {
                state: '123',
                code: 'code'
              }
            };
            
            handler(req, res);
          });

          it('should send the view', () => {
            assert.equal(res.send.args[0][0], '<p>You can close this tab</p>');
          });

          it('should emit response event', () => {
            const event = mockedEvents.emit.args.shift();            
            assert.ok(event[0], 'response');
            assert.ok(event[1].state, '123');
            assert.ok(event[1].code, 'code');
          });
        });
      });
    });

    describe('when response mode is from_post', () => {
      const instance = new Server();    
      before((done) => {
        mockedExpress = {
          post: sinon.stub(),
          listen : sinon.stub(),
          use: sinon.stub()
        };

        instance.createServer('form_post', done);

        mockedExpress.listen.args[0][1]();
      });

      it('should define spinup a server', () => {
        assert.equal(mockedExpress.listen.args[0][0], 8000)
        assert.equal(typeof mockedExpress.listen.args[0][1], 'function')
      });

      it('should configure bodyparser', () => {
        assert.ok(mockedBodyParser.urlencoded.calledOnce);
        assert.equal(mockedBodyParser.urlencoded.args[0][0].extended, false)
        assert.ok(mockedBodyParser.json.calledOnce)
      })

      it('define post endpoint', () => {
        assert.equal(mockedExpress.post.args[0][0], '/')
        assert.equal(typeof mockedExpress.post.args[0][1], 'function')
      });
    });

    describe('when response mode is not found', () => {
      const instance = new Server();    
      before((done) => {
        mockedExpress = {
          get: sinon.stub(),
          listen : sinon.stub(),
          use: sinon.stub()
        };

        instance.createServer('', done);

        mockedExpress.listen.args[0][1]();
      });
      
      it('should define spinup a server', () => {
        assert.equal(mockedExpress.listen.args[0][0], 8000)
        assert.equal(typeof mockedExpress.listen.args[0][1], 'function')
      })

      it('define get endpoint', () => {
        assert.equal(mockedExpress.get.args[0][0], '/')
        assert.equal(typeof mockedExpress.get.args[0][1], 'function')
      });
    });
  });

  describe('on', () => {
    const instance = new Server();    
    const event = () => {};
    before(() => {
      instance.on('test', event);
    });

    it('should register an event', () => {
      const ev = mockedEvents.on.args.shift();
      assert.equal(ev[0], 'test');
      assert.equal(ev[1], event);
    })
  });

  describe('destroy', () => {

    describe('when server was not created', () => {
      const instance = new Server();    
      let destroy;
      before(() => {
        destroy = instance.destroy();
      });
  
      it('should not fail', () => {
        assert.ok(destroy);
      })
    });

    describe('when server was created', () => {
      const instance = new Server();    
      const mockedServer = {
        close: sinon.stub()
      };
      before(() => {
        mockedExpress = {
          get: sinon.stub(),
          listen : sinon.stub().returns(mockedServer)
        };
        instance.createServer().destroy();
      });
  
      it('should call destroy', () => {
        sinon.assert.called(mockedServer.close);
      })
    })
  });
});