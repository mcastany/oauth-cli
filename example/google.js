const Auth = require('../');

const server = (new Auth())
  .setDiscoveryUrl('https://accounts.google.com/.well-known/openid-configuration')
  .setClient({
    client_id: '421432764521-gmsvmjdu90bccnn6thf80g1ar4ig21gd.apps.googleusercontent.com',
    redirect_uri: 'http://127.0.0.1:8000',
    // code_challenge_method: 'S256'
  });

server.authenticate({ scope: 'openid', extras: { access_type: 'offline' } }, (err, res) =>{
  if (err) { return console.log(err); }
  console.log(`Successfully authenticated. access_token: ${res.access_token} refresh_token: ${res.refresh_token}`);
  const rt = res.refresh_token;

  return server.performRefreshTokenExchange({ refresh_token: res.refresh_token }, (err, res) => {
    if (err) { return console.log(err); }
    console.log(`Successfully refreshed token. access_token: ${res.access_token}`);
    
    return server.revokeRefreshToken({ refresh_token: rt }, (err) => {
      if (err) { return console.log(err); }
      console.log('Successfully revoked');
    });
  });
});
