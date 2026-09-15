#!/opt/puppetlabs/puppet/bin/ruby
# frozen_string_literal: true

require 'json'
require 'open3'

params = JSON.parse($stdin.read)
require File.join(params['_installdir'], 'openvox_ca', 'lib', 'puppet_x', 'openvox_ca', 'service')

begin
  bin = PuppetX::OpenvoxCa::Service.puppetdb_bin
  if bin.nil?
    puts JSON.generate({ 'status' => 'skipped', 'present' => false })
    exit 0
  end
  out, err, status = Open3.capture3(bin, 'ssl-setup', '-f')
  raise "puppetdb ssl-setup failed: #{(out + err).strip}" unless status.success?

  puts JSON.generate({ 'status' => 'changed', 'present' => true, 'output' => out.strip })
rescue StandardError => e
  puts JSON.generate({ '_error' => { 'msg' => "#{e.class}: #{e.message}", 'kind' => 'openvox_ca/refresh_puppetdb_ssl', 'details' => {} } })
  exit 1
end
