const cliOAuth = require('../');
const refresh_token = 'aYSDNMW1phJ2yx59tBFCZjPjUUQx9mlQvBS6kz6AHlu3I';
const revoke = false;
const server = (new cliOAuth())
  .setDiscoveryUrl('https://accounts.google.com/.well-known/openid-configuration')
  .setClient({
    client_id: '421432764521-gmsvmjdu90bccnn6thf80g1ar4ig21gd.apps.googleusercontent.com',
    redirect_uri: 'http://127.0.0.1:8000',
    code_challenge_method: 'S256'
    
  });

if(true){
  if (false && refresh_token){
    if(revoke){
      return server.revokeRefreshToken({ refresh_token: refresh_token }, (err, res) => {
        console.log('revoked', err || res)
      });
    }

    return server.performRefreshTokenExchange({ refresh_token: refresh_token }, (err, res) => {
      console.log('rt exchange', err || res);
    });
  }

  server.authenticate({ scope: 'openid',  }, (err, res) =>{
    console.log('authenticate', err || res);

    console.log(res.access_token);

    if(res && res.access_token){
      server.userInfo(res.access_token, (err, res) => {
        console.log('userinfo', err || res)
      })
    }
  });
}

if(false){
  const server2 = (new cliOAuth())
    .setInternalServer({ port: 8001 })
    .setDiscoveryUrl('https://github-mcastany.auth0.com/.well-known/openid-configuration') // You can use this or setAuthorizationServer
    .setClient({
      client_id: 'jDnERxH1euNJHp8iekBZSJwTvm9gUtiT',
      redirect_uri: 'http://127.0.0.1:8001',
      code_challenge_method: 'S256'
    });

  server2.authenticate({ scope: 'openid' }, (err, res) =>{
    console.log('authenticate', err || res);

    if(res && res.access_token){
      server2.userInfo(res.access_token, (err, res) => {
        console.log('userinfo', err || res)
      })
    }
  });
}
