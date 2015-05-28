module.exports = function() {

  var http = require('http');
  var url = require('url');

  return function(auth, settings, callback) {
    var service = url.parse(settings.url);
    http.get({
      hostname: service.hostname,
      port: service.port || 80,
      path: service.path,
      auth: auth.login + ':' + auth.password
    }, function(response) {
      if (response.statusCode=='200') {
        auth.success = true;
      }
      callback(auth.success);
    });
  };

}();
