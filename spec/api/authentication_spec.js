var test = require('frisby');

test.create('Dummy authentication OK')
  .get('http://traduxio.local:1337/works/')
  .auth('alice', 'whiterabbit')
  .expectStatus(200)
  .toss();
test.create('Dummy authentication KO')
  .get('http://traduxio.local:1337/works/')
  .auth('alice', 'rabbit')
  .expectStatus(401)
  .toss();
