const app = require('express')();
const vhost = require('vhost');
const proxy = require('http-proxy-middleware');
const configuration = require('./config');

const port = configuration.port;

let hideLocationParts = function(site) {
  return (response) => {
    if (site.hideLocationParts && response.headers.location) {
      let locationParts = response.headers.location.split('/');
      locationParts.splice(3,site.hideLocationParts);
      response.headers.location = locationParts.join('/');
    }
  }
}

for (let site of configuration.sites) {
  app.use(vhost(site.hostProxy, proxy({
    target: `http://${site.host||'localhost'}:${site.port||80}`,
    pathRewrite: {
      '': site.path||''
    },
    onProxyRes: hideLocationParts(site)
  })));
}

app.listen(port, function() {
  console.log(`Test it on http://localhost:${port}`);
});
