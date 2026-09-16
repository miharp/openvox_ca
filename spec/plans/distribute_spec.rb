# frozen_string_literal: true

require_relative 'spec_helper'

describe 'openvox_ca::distribute' do
  let(:ca) { PlanFixtures::CA }
  let(:agents) { %w[agent01.example.com agent02.example.com] }
  let(:source) do
    { 'bundle' => 'QkVHSU4=', 'crl' => 'Q1JM', 'certificates' => [{ 'subject' => '/CN=Puppet CA: puppet.example.com', 'not_after' => '2041-09-12T00:00:00Z' }] }
  end

  it 'refuses more than one CA target' do
    result = run_plan('openvox_ca::distribute', 'ca' => agents, 'targets' => agents)
    expect(result.value.kind).to eq('openvox_ca/bad-ca-target')
  end

  it 'refetches by default: reads the bundle once, removes each copy with a triggered run, and reports each copy expiry' do
    expect_task('openvox_ca::read_ca_bundle').with_targets(ca).be_called_times(1).always_return(source)
    expect_task('openvox_ca::remove_localcacert').with_targets(agents).with_params('trigger_run' => true, '_catch_errors' => true)
                                                 .always_return(distribute_result)
    expect_task('openvox_ca::upload_ca').not_be_called
    expect_out_message.with_params('agent01.example.com          refetch  CA copy now expires 2041-09-12')

    result = run_plan('openvox_ca::distribute', 'ca' => ca, 'targets' => agents)
    expect(result).to be_ok
    expect(result.value.keys).to match_array(agents)
  end

  it 'uploads the bundle and CRL from the CA host with the restart flag' do
    allow_task('openvox_ca::read_ca_bundle').always_return(source)
    expect_task('openvox_ca::upload_ca').with_targets(agents)
                                        .with_params('bundle' => 'QkVHSU4=', 'crl' => 'Q1JM', 'restart_agent' => false, '_catch_errors' => true)
                                        .always_return(distribute_result)
    expect_task('openvox_ca::remove_localcacert').not_be_called

    expect(run_plan('openvox_ca::distribute', 'ca' => ca, 'targets' => agents, 'strategy' => 'upload', 'restart_agent' => false)).to be_ok
  end

  it 'fails with distribute-failed when any target fails, after reporting the rest' do
    allow_task('openvox_ca::read_ca_bundle').always_return(source)
    expect_task('openvox_ca::remove_localcacert').return_for_targets(
      'agent01.example.com' => distribute_result,
      'agent02.example.com' => { '_error' => { 'kind' => 'puppetlabs.tasks/connect-error', 'msg' => 'Connection refused', 'details' => {} } },
    )
    expect_out_message.with_params('agent02.example.com          FAILED   Connection refused')

    result = run_plan('openvox_ca::distribute', 'ca' => ca, 'targets' => agents)
    expect(result).not_to be_ok
    expect(result.value.kind).to eq('openvox_ca/distribute-failed')
    expect(result.value.message).to eq('Distribution failed on agent02.example.com')
  end

  it 'rejects an unknown strategy before touching the CA host' do
    expect_task('openvox_ca::read_ca_bundle').not_be_called
    result = run_plan('openvox_ca::distribute', 'ca' => ca, 'targets' => agents, 'strategy' => 'teleport')
    expect(result).not_to be_ok
  end
end
