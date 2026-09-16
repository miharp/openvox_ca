# frozen_string_literal: true

require_relative 'spec_helper'

describe 'openvox_ca::check' do
  let(:agents) { %w[agent01.example.com agent02.example.com] }

  it 'refuses more than one CA target before running anything' do
    result = run_plan('openvox_ca::check', 'ca' => agents)
    expect(result).not_to be_ok
    expect(result.value.kind).to eq('openvox_ca/bad-ca-target')
  end

  it 'checks the CA with the audit mode and every other target with the warn window, and returns both reports' do
    expect_task('openvox_ca::check_ca').with_targets(PlanFixtures::CA).with_params('warn_days' => 30, 'issued' => 'all', 'section' => 'server')
                                       .always_return(ca_report(issued: { 'total' => 3, 'ok' => 3, 'warn' => 0, 'expired' => 0, 'revoked' => 0 }))
    expect_task('openvox_ca::check_host_cert').with_targets(agents).with_params('warn_days' => 30, '_catch_errors' => true)
                                              .always_return(host_report)
    expect_out_message.with_params('Issued certificates on puppet.example.com: 3 total, 0 due within 30 days, 0 expired, 0 revoked')

    result = run_plan('openvox_ca::check', 'ca' => PlanFixtures::CA, 'targets' => agents, 'warn_days' => 30, 'issued' => 'all')
    expect(result).to be_ok
    expect(result.value['ca']['layout']).to eq('single')
    expect(result.value['hosts'].keys).to match_array(agents)
  end

  it 'defaults to listing only the due issued certificates and marks revoked ones in the table' do
    expect_task('openvox_ca::check_ca').with_params('warn_days' => 90, 'issued' => 'due', 'section' => 'server')
                                       .always_return(ca_report(items: [ca_item, issued_item('agent07.example.com', revoked: true)],
                                                                issued: { 'total' => 5, 'ok' => 4, 'warn' => 1, 'expired' => 0, 'revoked' => 1 }))
    expect_out_message.with_params('warn     puppet.example.com           issued_cert    2026-11-02     47  /CN=agent07.example.com (revoked)')

    result = run_plan('openvox_ca::check', 'ca' => PlanFixtures::CA)
    expect(result).to be_ok
    expect(result.value['hosts']).to eq({})
  end

  it 'keeps going when a host cannot be checked and names it' do
    allow_task('openvox_ca::check_ca').always_return(ca_report)
    expect_task('openvox_ca::check_host_cert').return_for_targets(
      'agent01.example.com' => host_report,
      'agent02.example.com' => { '_error' => { 'kind' => 'puppetlabs.tasks/connect-error', 'msg' => 'Connection refused', 'details' => {} } },
    )
    expect_out_message.with_params('Could not check: agent02.example.com')

    result = run_plan('openvox_ca::check', 'ca' => PlanFixtures::CA, 'targets' => agents)
    expect(result).to be_ok
    expect(result.value['hosts']['agent01.example.com']['status']).to eq('ok')
    expect(result.value['hosts']['agent02.example.com']).to have_key('_error')
  end
end
