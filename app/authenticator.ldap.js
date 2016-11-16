module.exports = function() {

  var LDAP = require('ldapjs');
  var CRYPTO = require ('crypto');

  var cache = {
    set: function(url, id, err) {
      if (!this[url]) {
        this[url] = {};
      }
      this[url][id] = {
        success: !err,
        timeOut: setTimeout(this.remove, err? 300000:900000, url, id)
      };
    },
    get: function(url, id) {
      return this[url]? this[url][id] : null;
    },
    remove: function(url, id) {
      if (this[url]) {
        delete this[url][id];
        if (this[url]==={}) {
          delete this[url];
        }
      }
    }
  };

  function closeSocket(ldap) {
    if(ldap.socket != undefined) {//older ldapjs version
      ldap.socket.end();
    }
    if(ldap._socket != undefined) { //newer ldapjs version
      ldap._socket.end();
    }
  }

  return function(auth, settings, callback) {
    var url = settings.url;
    var ldapReq = settings.id + '=' + auth.login + ',' + settings.dn;
    var id = CRYPTO.createHash('sha1')
      .update(url)
      .update(ldapReq)
      .update(auth.password || "")
      .digest('hex');
    var cachedValue = cache.get(url, id);
    if (cachedValue) {
      auth.success = cachedValue.success;
      callback(true);
    } else {
      var ldap = LDAP.createClient({url: url});
      ldap.search(ldapReq, {}, function(err, res) {
        if (err) { // network error
          callback(false);
        } else {
          res.on('error', function(err) { // ldap error including 'not found'
            closeSocket(ldap);
            callback(false);
          });
          res.on('searchEntry', function() {
            ldap.bind(ldapReq, auth.password, function(err) {
              auth.success = !err;
              cache.set(url, id, err);
              closeSocket(ldap);
              callback(true);
            });
          });
        }
      });
    }
  };

}();
