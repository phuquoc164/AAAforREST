var test = require('frisby');

test.create('Dummy authentication with a valid user')
  .get('http://cassandre.local:1337/text/Wonderland/')
  .auth('alice', 'whiterabbit')
  .expectStatus(200)
  .toss();
test.create('Dummy authentication with an invalid user')
  .get('http://cassandre.local:1337/text/Wonderland/')
  .auth('alice', 'rabbit')
  .expectStatus(401)
  .toss();
