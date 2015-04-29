var test = require('frisby');

test.create('Preserve HTTP basic authentication')
  .get('http://couchdb.local:1337/_active_tasks')
  .auth('carroll', 'curiouser')
  .expectStatus(200)
  .toss();
test.create('Preserve cookie authentication')
  .post('http://couchdb.local:1337/_session', {name:'carroll', password:'curiouser'})
  .expectStatus(200)
  .after(function(error, resource) {
    test.create('Preserve cookie authentication use')
      .get('http://couchdb.local:1337/_active_tasks')
      .addHeader('Cookie', resource.headers['set-cookie'])
      .expectStatus(200)
      .toss();
  })
  .toss();
