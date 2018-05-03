const app = require('express')();
const vhost = require('vhost');
const configuration = require('./config');

const port = configuration.port;

for (let site of configuration.sites) {
  app.use(vhost(site.hostProxy, (request, response) => response.send(site.hostProxy)));
}

app.listen(port, function() {
  console.log(`Test it on http://localhost:${port}`);
});
