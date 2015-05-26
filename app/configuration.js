module.exports = function() {
  var fs = require('fs');
  var configuration = (fs.existsSync('conf/config.js')||fs.existsSync('conf/config.json'))
    ? require('../conf/config')
    : {};
  if (!configuration.sites) {
    console.log('Please configure the reverse proxy correctly.');
    process.exit(1);
  }
  configuration.port = configuration.port || 80;
  configuration.site = function(request) {
    var requested_host = request.headers.host;
    var found = false;
    var i = 0;
    while (!found && i<configuration.sites.length) {
      var site_host = configuration.sites[i].hostProxy;
      var re = new RegExp(site_host + '(:' + configuration.port + ')?', "i");
      found = re.test(requested_host);
      if (!found) {
        i++;
      }
    }
    return found? configuration.sites[i] : null;
  };

  return configuration;
}();
