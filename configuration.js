module.exports = function() {
  var fs = require('fs');
  var configuration = (fs.existsSync('config.js')||fs.existsSync('config.json'))
    ? require('./config')
    : {};
  if (!configuration.sites || !configuration.port) {
    console.log('Please configure the reverse proxy correctly.');
    process.exit(1);
  }
  return configuration;
}();
