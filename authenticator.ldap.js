module.exports = function() {

  var configuration = require('./configuration');
  var LDAP = require('ldapjs');
  var CRYPTO = require ('crypto');
  var URL = require('url');

  var cache = {};

  var flush = function(id, server) {
    console.log('flushing ldap auth ' + id + ' from server ' + server);
    delete cache[server][id];
    if (cache[server] === {}) delete cache[server];
  };

  return function(context, callback) {
    var site_ldap = configuration.sites[context.conf].ldap;
    var negativeCacheTime = (site_ldap.negativeCacheTime || 300) /* 5 minutes*/ * 1000 /*ms*/;
    var positiveCacheTime = (site_ldap.positiveCacheTime || 900) /* 15 minutes*/ * 1000 /*ms*/;

    var url = site_ldap.url;
    var ldapReq = site_ldap.id + context.login + ',' + site_ldap.cn; //do not manage more than one dc information
    var id = CRYPTO.createHash('sha1')
      .update(url).update(ldapReq).update(context.pw)
      .digest('hex');
    var login = context.login;
    if (typeof site_ldap.domain != 'undefined') {
      var domain = site_ldap.domain;
      if (domain && typeof domain == 'string') {
        domain = site_ldap.domain;
      } else {
        domain = URL.parse(url).host;
      }
      if (domain)
        login = context.login + '@' + domain;
    }
    if (!cache[url] || !cache[url][id]) {
      console.log('Logging in ' + ldapReq + ' into ' + url);
      if (!cache[url]) {
        cache[url] = {};
      }
      if (!(id in cache[url])) {
        cache[url][id] = {};
      }
      var ldap = LDAP.createClient({
        'url': url
      });
      ldap.bind(ldapReq, context.pw, function(err) {
        if ('timeOut' in cache[url][id]) {
          clearTimeout(cache[url][id].timeOut);
        }
        cache[url][id].err = err;
        cache[url][id].timeOut =
          setTimeout(flush, err?negativeCacheTime:positiveCacheTime, id, url);
        var isAuthentified = !err;
        if (isAuthentified) { 
          context.login = login;
          ldap.unbind(function () {
            callback(isAuthentified);
          });
        } else {
          console.log('LDAP error: ' + JSON.stringify(err));
          callback(isAuthentified);
        }
      });
    } else {
      if (!cache[url][id].err) context.login = login;
      callback(!cache[url][id].err);
    }
  };

}();
