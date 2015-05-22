require 'capybara/rspec'
require 'capybara/webkit'

Capybara.run_server = false
Capybara.default_driver = :webkit
Capybara.app_host = 'http://auth.local:1337'

RSpec.configure do |config|
  config.before(:each) do
    page.driver.allow_url 'auth.local'
    page.driver.allow_url 'couchdb.local'
  end
end

def a_string()
  s = ('a'..'z').to_a.shuffle[0,8].join
end
