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
  return configuration;
}();
