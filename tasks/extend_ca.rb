#!/opt/puppetlabs/puppet/bin/ruby
# frozen_string_literal: true

require 'json'

params = JSON.parse($stdin.read)
lib = File.join(params['_installdir'], 'openvox_ca', 'lib', 'puppet_x', 'openvox_ca')
%w[inspect extend puppet_settings service ca_cli].each { |f| require File.join(lib, f) }

def fail_task(message, kind)
  puts JSON.generate({ '_error' => { 'msg' => message, 'kind' => kind, 'details' => {} } })
  exit 1
end

begin
  dry_run = params.fetch('dry_run', false)
  force = params.fetch('force', false)
  raw_ttl = params.fetch('ttl', '15y')
  ttl = PuppetX::OpenvoxCa::Extend.parse_ttl(raw_ttl)
  crls = params.fetch('crls', 'expired').to_sym
  warning = dry_run ? nil : PuppetX::OpenvoxCa::Service.refuse_if_running!(force: force)

  use_gem = case params.fetch('implementation', 'auto')
            when 'library' then false
            when 'gem'
              PuppetX::OpenvoxCa::CaCli.extend_available? || raise(PuppetX::OpenvoxCa::Extend::Error, 'puppetserver ca extend is not available on this host; use implementation=auto or library')
            else PuppetX::OpenvoxCa::CaCli.extend_available?
            end

  names = %w[cadir cacert cakey rootkey cacrl localcacert hostcert hostcrl certname]
  settings = PuppetX::OpenvoxCa::PuppetSettings.print(names, section: params.fetch('section', 'server'))
  now = Time.now

  report = {
    'status' => dry_run ? 'dry_run' : 'changed',
    'implementation' => use_gem ? 'gem' : 'library',
    'certname' => settings['certname'],
    'ttl_seconds' => ttl,
    'warning' => warning,
  }

  if use_gem && !dry_run
    result = PuppetX::OpenvoxCa::CaCli.extend(settings, ttl: raw_ttl, crls: crls, force: force, now: now)
    report['planned_writes'] = result['written']
    report['output'] = result['output']
  else
    # The dry run always uses the library to compute the change, even when the
    # gem would do the real work, so nothing is written.
    result = PuppetX::OpenvoxCa::Extend.compute(settings, ttl_seconds: ttl, crls: crls, now: now)
    report['planned_writes'] = PuppetX::OpenvoxCa::Extend.planned_writes(settings, result).keys
    result.merge!(PuppetX::OpenvoxCa::Extend.apply(settings, result, now: now)) unless dry_run
  end

  report.merge!(
    'layout' => result['layout'],
    'not_after' => result['not_after'],
    'certificates' => result['certificates'],
    'crls' => result['crl_files'].flat_map { |path, data| data['items'].map { |i| i.merge('file' => path) } },
    'written' => result['written'],
    'backups' => result['backups'],
  )
  puts JSON.generate(report)
rescue PuppetX::OpenvoxCa::Extend::Error => e
  fail_task(e.message, 'openvox_ca/refused')
rescue StandardError => e
  fail_task("#{e.class}: #{e.message}", 'openvox_ca/extend_ca')
end
