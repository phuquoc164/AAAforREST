require 'spec_helper'

feature 'Register' do

  scenario 'as a new user' do
    visit '/register.html#http://couchdb.local:1337/_session'
    fill_in 'Username', :with => a_string()
    fill_in 'Password', :with => 'secret'
    fill_in 'Confirm password', :with => 'secret'
    click_on 'submit'
    expect(page).to have_content "Your account has been created"
  end

  scenario 'not as an existing user' do
    visit '/register.html#http://couchdb.local:1337/_session'
    fill_in 'Username', :with => 'hatter'
    fill_in 'Password', :with => 'secret'
    fill_in 'Confirm password', :with => 'secret'
    click_on 'submit'
    expect(page).to have_content 'username already exists'
  end

end
