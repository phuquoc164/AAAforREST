module.exports = function() {

  var configuration = require('./configuration');
  var loggers = require('winston').loggers;

  function addLogger(name) {
    loggers.add(name, {
      console: {timestamp:true, json:false, colorize:true},
      file: {
        timestamp:true, json:false, filename: 'log/' + name + '.log'
      }
    });
  }
  configuration.sites.forEach(function(site) {
    addLogger(site.hostProxy);
  });
  addLogger('misc');

  return function(context, err, code) {
    var request = context.requestIn;
    var site = configuration.sites[context.conf];
    var logger = loggers.get(site?site.hostProxy:'misc');
    logger.info(
      (context.login? context.login + '@' : '')
      + (request.headers['x-forwarded-for'] || request.connection.remoteAddress)
      + '\t' + request.method 
      + '\t' + request.headers.host + request.url 
      + '\t' + code
    );
  };

}();
