require 'capybara/rspec'
require 'capybara/webkit'

Capybara.run_server = false
Capybara.default_driver = :webkit
Capybara.app_host = 'http://auth.local:1337'

Capybara::Webkit.configure do |config|
  config.allow_url 'auth.local'
  config.allow_url 'couchdb.local'
end

def a_string()
  s = ('a'..'z').to_a.shuffle[0,8].join
end
