# frozen_string_literal: true

require 'spec_helper'
require_relative '../../../support/ca_fixtures'
require_relative '../../../../lib/puppet_x/openvox_ca/distribute'

describe PuppetX::OpenvoxCa::Distribute do
  let(:layout) { CaFixtures.intermediate_ca }
  let(:agent) { CaFixtures.single_ca }

  after do
    FileUtils.rm_rf(layout.dir)
    FileUtils.rm_rf(agent.dir)
  end

  describe '.install' do
    it 'replaces the agent copies with backups and reports the new bundle' do
      report = described_class.install(agent.settings, File.read(layout.cacert), File.read(layout.cacrl))
      expect(report['written']).to contain_exactly(agent.localcacert, agent.hostcrl)
      expect(report['backups'].length).to eq(2)
      expect(File.read(agent.localcacert)).to eq(File.read(layout.cacert))
      expect(File.read(agent.hostcrl)).to eq(File.read(layout.cacrl))
      expect(report['items'].map { |i| i['subject'] }).to eq(['/CN=Puppet CA: puppet.example.com', '/CN=Puppet Root CA: 0123456789abcdef'])
    end

    it 'refuses an empty or unparsable bundle without touching anything' do
      before = File.read(agent.localcacert)
      expect { described_class.install(agent.settings, 'not a certificate') }.to raise_error(described_class::Error)
      expect { described_class.install(agent.settings, "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n") }.to raise_error(OpenSSL::X509::CertificateError)
      expect(File.read(agent.localcacert)).to eq(before)
    end
  end

  describe '.remove' do
    it 'moves the bundle and CRL aside' do
      report = described_class.remove(agent.settings)
      expect(report['backups'].length).to eq(2)
      expect(File.exist?(agent.localcacert)).to be(false)
      expect(File.exist?(agent.hostcrl)).to be(false)
      expect(report['backups']).to all(satisfy { |b| File.exist?(b) })
    end
  end
end
