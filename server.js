const express = require('express');
const vhost = require('vhost');
const proxy = require('http-proxy-middleware');
const cors = require('cors');
const configuration = require('./config');

let hideLocationParts = function(site) {
  return (response) => {
    if (site.hideLocationParts && response.headers.location) {
      let locationParts = response.headers.location.split('/');
      locationParts.splice(3,site.hideLocationParts);
      response.headers.location = locationParts.join('/');
    }
  }
}

let proxyVhost = function(site) {
  let result = express();
  if (site.origin) {
    let corsPolicy = cors({
      origin: site.origin,
      credentials: true
    });
    result.options('*', corsPolicy);
    result.use(corsPolicy);
  }
  result.use(proxy({
    target: `http://${site.host||'localhost'}:${site.port||80}`,
    pathRewrite: {
      '': site.path||''
    },
    onProxyRes: hideLocationParts(site)
  }));
  return result;
}

const app = express();
const port = configuration.port;

for (let site of configuration.sites) {
  app.use(vhost(site.hostProxy, proxyVhost(site)));
}

app.listen(port, function() {
  console.log(`Test it on http://localhost:${port}`);
});
