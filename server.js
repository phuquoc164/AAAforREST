const app = require('express')();
const configuration = require('./config');

const port = configuration.port;

app.listen(port, function() {
  console.log(`Test it on http://localhost:${port}`);
});
