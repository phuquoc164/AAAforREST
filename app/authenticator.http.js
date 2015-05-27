module.exports = function() {

  var http = require('http');
  var url = require('url');

  return function(context, settings, callback) {
    var service = url.parse(settings.url);
    var request = context.requestIn;
    http.get({
      hostname: service.hostname,
      port: service.port || 80,
      path: service.path,
      auth: request.auth.login + ':' + request.auth.password
    }, function(response) {
      if (response.statusCode=='200') {
        request.auth.success = true;
      }
      callback(request.auth.success);
    });
  };

}();
