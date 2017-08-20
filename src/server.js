const EventEmitter = require('events');
const express = require('express');
const bodyParser = require('body-parser');
const RESPONSE_MODES = {
  query: {
    method: 'get',
    location: 'query'
  },
  form_post: {
    method: 'post',
    location: 'body'
  }
}

function Server(settings){
  settings =  settings || { port : 8000, logger: console };
  this.port = settings.port;
  this.eventEmitter = new EventEmitter();

  this.logger = settings.logger;
  this.view =  settings.view || '<p>You can close this tab</p>';
  return this;
}

Server.prototype.on = function(event_name, cb){
  this.eventEmitter.on(event_name, cb);
  return this;
}

Server.prototype.createServer = function(rm, cb){
  const self = this;
  const response_mode = RESPONSE_MODES[rm] || RESPONSE_MODES['query'];
  const app = express();

  if(rm === 'form_post'){
    app.use(bodyParser.urlencoded({ extended: false }));
    app.use(bodyParser.json());
  }

  app[response_mode.method]('/', function (req, res) {
    res.send(self.view);
    var params = req[response_mode.location];
    if (params.error){
      return self.eventEmitter.emit('error', { error: params.error });
    }
    
    if (params.code) {
      self.eventEmitter.emit('response', { state: params.state, code: params.code })    
    }
  });

  this.server = app.listen(this.port, () => {
    self.logger.info('server listening on port ' + this.port);
    self.eventEmitter.emit('loaded')
    cb();
  });

  return this;
}

Server.prototype.destroy = function(){
  if (this.server && typeof this.server.close === 'function'){

    this.server.close();
    delete this.server;
  }
  return this;
}

module.exports = Server;