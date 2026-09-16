# frozen_string_literal: true

require_relative 'spec_helper'

describe 'openvox_ca::extend' do
  let(:ca) { PlanFixtures::CA }
  let(:health_url) { 'curl -sSf --insecure https://127.0.0.1:8140/status/v1/simple' }

  def stub_healthy_restart
    expect_command('systemctl start puppetserver').with_targets(ca)
    allow_command(health_url).with_targets(ca)
  end

  describe 'guards that run before the server is stopped' do
    it 'refuses more than one CA target' do
      result = run_plan('openvox_ca::extend', 'ca' => %w[a.example.com b.example.com])
      expect(result.value.kind).to eq('openvox_ca/bad-ca-target')
    end

    it 'refuses an externally issued CA' do
      allow_task('openvox_ca::check_ca').always_return(ca_report(layout: 'intermediate', external: ['/CN=Corp Root']))
      expect_command('systemctl stop puppetserver').not_be_called
      result = run_plan('openvox_ca::extend', 'ca' => ca, 'force' => true)
      expect(result.value.kind).to eq('openvox_ca/external-ca')
    end

    it 'refuses when nothing is due unless forced' do
      allow_task('openvox_ca::check_ca').always_return(ca_report(status: 'ok'))
      expect_command('systemctl stop puppetserver').not_be_called
      result = run_plan('openvox_ca::extend', 'ca' => ca)
      expect(result.value.kind).to eq('openvox_ca/nothing-due')
    end

    it 'asks the check to skip the issued-certificate audit' do
      expect_task('openvox_ca::check_ca').with_params('warn_days' => 90, 'issued' => 'none', 'section' => 'server').always_return(ca_report(status: 'ok'))
      run_plan('openvox_ca::extend', 'ca' => ca)
    end
  end

  describe 'dry run' do
    it 'computes the change without stopping anything and returns no after report' do
      allow_task('openvox_ca::check_ca').always_return(ca_report(status: 'warn'))
      expect_task('openvox_ca::extend_ca').with_params('ttl' => '400d', 'crls' => 'all', 'implementation' => 'library', 'dry_run' => true, 'force' => false, 'section' => 'server')
                                          .always_return(extend_result.merge('status' => 'dry_run', 'planned_writes' => %w[/a /b]))
      expect_command('systemctl stop puppetserver').not_be_called
      expect_out_message.with_params('Dry run: would re-sign 1 certificate(s) to expire 2041-09-12 using the library')

      result = run_plan('openvox_ca::extend', 'ca' => ca, 'dry_run' => true, 'ttl' => '400d', 'crls' => 'all', 'implementation' => 'library')
      expect(result).to be_ok
      expect(result.value['after']).to be_nil
      expect(result.value['extend']['status']).to eq('dry_run')
    end
  end

  describe 'the full sequence' do
    before do
      allow_task('openvox_ca::check_ca').always_return(ca_report(status: 'warn'))
      expect_command('systemctl stop puppetserver').with_targets(ca)
    end

    it 'extends, regenerates the server certificate, refreshes OpenVoxDB, restarts both, and reports before and after' do
      expect_task('openvox_ca::extend_ca').with_params('ttl' => '15y', 'crls' => 'expired', 'implementation' => 'auto', 'dry_run' => false, 'force' => false, 'section' => 'server', '_catch_errors' => true)
                                          .always_return(extend_result(implementation: 'gem'))
      expect_task('openvox_ca::regen_primary_cert').with_params('dns_alt_names' => %w[puppet puppet.example.com], 'force' => false, '_catch_errors' => true)
                                                   .always_return(regen_result)
      expect_task('openvox_ca::refresh_puppetdb_ssl').with_params('_catch_errors' => true).always_return('present' => true, 'status' => 'changed')
      expect_command('systemctl restart puppetdb').with_targets(ca)
      expect_out_message.with_params('  re-signed with puppetserver ca extend')
      expect_out_message.with_params('  old certificate had alt names: DNS:puppet')
      stub_healthy_restart

      result = run_plan('openvox_ca::extend', 'ca' => ca, 'regen_primary_cert' => true, 'dns_alt_names' => %w[puppet puppet.example.com])
      expect(result).to be_ok
      expect(result.value.keys).to contain_exactly('before', 'extend', 'after')
      expect(result.value['extend']['implementation']).to eq('gem')
    end

    it 'skips regeneration and OpenVoxDB when not asked or not installed' do
      allow_task('openvox_ca::extend_ca').always_return(extend_result)
      expect_task('openvox_ca::regen_primary_cert').not_be_called
      expect_task('openvox_ca::refresh_puppetdb_ssl').always_return('present' => false)
      expect_command('systemctl restart puppetdb').not_be_called
      stub_healthy_restart

      expect(run_plan('openvox_ca::extend', 'ca' => ca)).to be_ok
    end

    it 'leaves OpenVoxDB alone with restart_puppetdb=false' do
      allow_task('openvox_ca::extend_ca').always_return(extend_result)
      expect_task('openvox_ca::refresh_puppetdb_ssl').not_be_called
      stub_healthy_restart

      expect(run_plan('openvox_ca::extend', 'ca' => ca, 'restart_puppetdb' => false)).to be_ok
    end
  end

  describe 'recovery when a step fails after the server was stopped' do
    before do
      allow_task('openvox_ca::check_ca').always_return(ca_report(status: 'warn'))
      expect_command('systemctl stop puppetserver').with_targets(ca)
    end

    it 'starts the server again and fails with the extend task error, skipping the later steps' do
      expect_task('openvox_ca::extend_ca').error_with('kind' => 'openvox_ca/refused', 'msg' => 'bundle holds 3 certificates')
      expect_task('openvox_ca::regen_primary_cert').not_be_called
      expect_task('openvox_ca::refresh_puppetdb_ssl').not_be_called
      expect_command('systemctl start puppetserver').with_targets(ca)

      result = run_plan('openvox_ca::extend', 'ca' => ca, 'regen_primary_cert' => true)
      expect(result).not_to be_ok
      expect(result.value.kind).to eq('openvox_ca/refused')
      expect(result.value.message).to eq('bundle holds 3 certificates')
    end

    it 'starts the server again when the certificate regeneration fails' do
      allow_task('openvox_ca::extend_ca').always_return(extend_result)
      expect_task('openvox_ca::regen_primary_cert').error_with('kind' => 'openvox_ca/regen_primary_cert', 'msg' => 'generate failed. Restored /x')
      expect_task('openvox_ca::refresh_puppetdb_ssl').not_be_called
      expect_command('systemctl start puppetserver').with_targets(ca)

      result = run_plan('openvox_ca::extend', 'ca' => ca, 'regen_primary_cert' => true)
      expect(result.value.kind).to eq('openvox_ca/regen_primary_cert')
    end

    it 'starts the server again when the OpenVoxDB refresh fails' do
      allow_task('openvox_ca::extend_ca').always_return(extend_result)
      expect_task('openvox_ca::refresh_puppetdb_ssl').error_with('kind' => 'openvox_ca/refresh_puppetdb_ssl', 'msg' => 'ssl-setup failed')
      expect_command('systemctl restart puppetdb').not_be_called
      expect_command('systemctl start puppetserver').with_targets(ca)

      result = run_plan('openvox_ca::extend', 'ca' => ca)
      expect(result.value.kind).to eq('openvox_ca/refresh_puppetdb_ssl')
    end

    it 'starts the server again when the OpenVoxDB restart fails' do
      allow_task('openvox_ca::extend_ca').always_return(extend_result)
      allow_task('openvox_ca::refresh_puppetdb_ssl').always_return('present' => true)
      expect_command('systemctl restart puppetdb').error_with('kind' => 'puppetlabs.tasks/command-error', 'msg' => 'restart failed')
      expect_command('systemctl start puppetserver').with_targets(ca)

      result = run_plan('openvox_ca::extend', 'ca' => ca)
      expect(result).not_to be_ok
      expect(result.value.message).to eq('restart failed')
    end
  end
end
