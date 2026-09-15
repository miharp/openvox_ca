#!/opt/puppetlabs/puppet/bin/ruby
# frozen_string_literal: true

require 'json'

params = JSON.parse($stdin.read)
lib = File.join(params['_installdir'], 'openvox_ca', 'lib', 'puppet_x', 'openvox_ca')
%w[inspect extend puppet_settings service].each { |f| require File.join(lib, f) }

def fail_task(message, kind)
  puts JSON.generate({ '_error' => { 'msg' => message, 'kind' => kind, 'details' => {} } })
  exit 1
end

begin
  dry_run = params.fetch('dry_run', false)
  ttl = PuppetX::OpenvoxCa::Extend.parse_ttl(params.fetch('ttl', '15y'))
  crls = params.fetch('crls', 'expired').to_sym
  warning = dry_run ? nil : PuppetX::OpenvoxCa::Service.refuse_if_running!(force: params.fetch('force', false))

  names = %w[cadir cacert cakey rootkey cacrl localcacert hostcert hostcrl certname]
  settings = PuppetX::OpenvoxCa::PuppetSettings.print(names, section: params.fetch('section', 'server'))
  now = Time.now
  result = PuppetX::OpenvoxCa::Extend.compute(settings, ttl_seconds: ttl, crls: crls, now: now)

  report = {
    'status' => dry_run ? 'dry_run' : 'changed',
    'certname' => settings['certname'],
    'layout' => result['layout'],
    'ttl_seconds' => ttl,
    'not_after' => result['not_after'],
    'certificates' => result['certificates'],
    'crls' => result['crl_files'].flat_map { |path, data| data['items'].map { |i| i.merge('file' => path) } },
    'planned_writes' => PuppetX::OpenvoxCa::Extend.planned_writes(settings, result).keys,
    'warning' => warning,
  }
  report.merge!(PuppetX::OpenvoxCa::Extend.apply(settings, result, now: now)) unless dry_run
  puts JSON.generate(report)
rescue PuppetX::OpenvoxCa::Extend::Error => e
  fail_task(e.message, 'openvox_ca/refused')
rescue StandardError => e
  fail_task("#{e.class}: #{e.message}", 'openvox_ca/extend_ca')
end
