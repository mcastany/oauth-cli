const cliOAuth = require('../');

 const server = (new cliOAuth())
  .setInternalServer({ port: 8001 })
  .setDiscoveryUrl('https://github-mcastany.auth0.com/.well-known/openid-configuration')
  .setAuthorizationServer({
    revocation_endpoint: 'https://github-mcastany.auth0.com/oauth/revoke' // This value is not in the well-known endpoint
  })
  .setClient({
    client_id: 'jDnERxH1euNJHp8iekBZSJwTvm9gUtiT',
    redirect_uri: 'http://127.0.0.1:8001',
    code_challenge_method: 'S256'
  });


server.authenticate({ scope: 'openid offline_access' }, (err, res) =>{
  if (err) { return console.log(err); }
  console.log(`Successfully authenticated. access_token: ${res.access_token} refresh_token: ${res.refresh_token}`);
  const rt = res.refresh_token;

  return server.performRefreshTokenExchange({ refresh_token: res.refresh_token }, (err, res) => {
    if (err) { return console.log(err); }
    console.log(`Successfully refreshed token. access_token: ${res.access_token}`);
    
    return server.revokeRefreshToken({ refresh_token: rt }, (err, res) => {
      if (err) { return console.log(err); }
      console.log('Successfully revoked');
    });
  });
});
