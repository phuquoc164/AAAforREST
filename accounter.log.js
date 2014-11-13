module.exports = function() {

  var fs = require('fs');
  var configuration = require('./configuration');

  return function(context, err, code) {
    var request = context.req;
    var site = configuration.sites[context.conf];
    var logFile = (site && site.logFile)? site.logFile : 'log/misc.log';
    var data = context.date.toISOString() 
      + '\t' + (context.login? context.login + '@' : '')
      + (request.headers['x-forwarded-for'] || request.connection.remoteAddress)
      + '\t' + request.method 
      + '\t' + request.headers.host + request.url 
      + '\t' + code;
    console.log(data);
    fs.appendFileSync(logFile, data + '\n');
  };

}();
