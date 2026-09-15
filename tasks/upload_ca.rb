#!/opt/puppetlabs/puppet/bin/ruby
# frozen_string_literal: true

require 'json'
require 'base64'
require 'open3'

params = JSON.parse($stdin.read)
lib = File.join(params['_installdir'], 'openvox_ca', 'lib', 'puppet_x', 'openvox_ca')
%w[inspect extend distribute puppet_settings service].each { |f| require File.join(lib, f) }

begin
  settings = PuppetX::OpenvoxCa::PuppetSettings.print(%w[localcacert hostcrl certname], section: 'agent')
  bundle = Base64.strict_decode64(params.fetch('bundle'))
  crl = params['crl'] && Base64.strict_decode64(params['crl'])
  report = PuppetX::OpenvoxCa::Distribute.install(settings, bundle, crl)
  restarted = false
  if params.fetch('restart_agent', true) && PuppetX::OpenvoxCa::Service.systemctl && PuppetX::OpenvoxCa::Service.active?('puppet')
    Open3.capture3(PuppetX::OpenvoxCa::Service.systemctl, 'restart', 'puppet')
    restarted = true
  end
  puts JSON.generate(report.merge('status' => 'changed', 'certname' => settings['certname'], 'agent_restarted' => restarted))
rescue PuppetX::OpenvoxCa::Distribute::Error => e
  puts JSON.generate({ '_error' => { 'msg' => e.message, 'kind' => 'openvox_ca/refused', 'details' => {} } })
  exit 1
rescue StandardError => e
  puts JSON.generate({ '_error' => { 'msg' => "#{e.class}: #{e.message}", 'kind' => 'openvox_ca/upload_ca', 'details' => {} } })
  exit 1
end
