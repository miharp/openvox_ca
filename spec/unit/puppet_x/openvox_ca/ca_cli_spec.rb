# frozen_string_literal: true

require 'spec_helper'
require 'json'
require_relative '../../../support/ca_fixtures'
require_relative '../../../../lib/puppet_x/openvox_ca/ca_cli'

# The `puppetserver ca extend` subcommand is proposed, not released. These
# specs run the wrapper against a stand-in that behaves the way the proposal
# describes: the general usage lists `extend` among the actions, and an
# extend re-signs the bundle with the module's own library, re-signs only
# expired CRLs, and writes the CA directory and the host's own copies without
# taking backups. The usage texts below are shaped like the real CLI's, which
# lists actions as an indented name, a tab, and a description, and answers an
# unknown action with "Unknown action" plus the whole usage and exit code 0.
describe PuppetX::OpenvoxCa::CaCli do
  def usage_without_extend
    <<~TXT
      Usage: puppetserver ca <action> [options]

      Available Actions:

        Certificate Actions (requires a running Puppet Server):

          clean\tRevoke cert(s) and remove related files from CA
          generate\tGenerate a new certificate signed by the CA
          sign\tSign certificate request(s)

        Administrative Actions (requires Puppet Server to be stopped):

          setup\tSetup a self-signed CA chain for Puppet Server

      Action Options:
        generate:
              --ttl TTL                    The time-to-live for each cert generated and signed
    TXT
  end

  def usage_with_extend
    usage_without_extend.sub("    setup\tSetup", "    extend\tRe-sign the CA certificate in place with a new validity period\n    setup\tSetup")
  end
  let(:workdir) { Dir.mktmpdir('openvox_ca_cli') }

  def inspect
    PuppetX::OpenvoxCa::Inspect
  end

  def extend
    PuppetX::OpenvoxCa::Extend
  end

  def log
    File.join(workdir, 'argv.log')
  end

  def fake
    File.join(workdir, 'puppetserver')
  end

  def lib
    File.expand_path('../../../../lib/puppet_x/openvox_ca', __dir__)
  end

  def write_fake(path, help: usage_with_extend, fail_with: nil)
    has_extend = help.include?("extend\t")
    lines = [
      '#!/usr/bin/env ruby',
      'args = ARGV.dup',
      "if args == %w[ca --help] || args.include?('--help') || !#{has_extend}",
      "  puts 'Unknown action: ' + args[1].to_s unless args == %w[ca --help]",
      "  puts #{help.inspect}",
      '  exit 0',
      'end',
      'exit 1 unless args.shift(2) == %w[ca extend]',
      "require 'json'",
      "require ENV['FAKE_LIB'] + '/extend'",
      "File.write(ENV['FAKE_LOG'], args.join(' '))",
    ]
    lines << "warn #{fail_with.inspect}; exit 2" if fail_with
    lines += [
      "ttl = args[args.index('--ttl') + 1]",
      "settings = JSON.parse(File.read(ENV['FAKE_SETTINGS']))",
      'result = PuppetX::OpenvoxCa::Extend.compute(settings, ttl_seconds: PuppetX::OpenvoxCa::Extend.parse_ttl(ttl), crls: :expired)',
      'PuppetX::OpenvoxCa::Extend.planned_writes(settings, result).each { |p, c| PuppetX::OpenvoxCa::Extend.write_atomically(p, c) }',
      "puts 'Extended the CA certificate to ' + result['not_after']",
    ]
    File.write(path, "#{lines.join("\n")}\n")
    File.chmod(0o755, path)
    path
  end

  def with_env(layout)
    ENV['FAKE_LIB'] = lib
    ENV['FAKE_LOG'] = log
    ENV['FAKE_SETTINGS'] = File.join(workdir, 'settings.json')
    File.write(ENV.fetch('FAKE_SETTINGS'), JSON.generate(layout.settings))
    yield
  ensure
    %w[FAKE_LIB FAKE_LOG FAKE_SETTINGS].each { |k| ENV.delete(k) }
  end

  after { FileUtils.rm_rf(workdir) }

  describe '.extend_available?' do
    it 'is true when the CLI lists extend among its actions' do
      expect(described_class.extend_available?(bin: write_fake(fake))).to be(true)
    end

    it 'is false for the current CLI, whose usage mentions --ttl for other actions but has no extend action' do
      expect(described_class.extend_available?(bin: write_fake(fake, help: usage_without_extend))).to be(false)
    end

    it 'is false without a usable binary' do
      expect(described_class.extend_available?(bin: File.join(workdir, 'nope'))).to be(false)
      expect(described_class.extend_available?(bin: nil)).to be(false)
    end

    it 'never runs the subcommand on a CLI without it, even when asked to extend' do
      write_fake(fake, help: usage_without_extend)
      layout = CaFixtures.single_ca
      expect { with_env(layout) { described_class.extend(layout.settings, ttl: '15y', bin: fake) } }.to raise_error(extend::Error, %r{did not move the expiry})
      FileUtils.rm_rf(layout.dir)
    end
  end

  describe '.extend' do
    let(:layout) { CaFixtures.intermediate_ca(ca_days: 10, revoked: [7]) }
    let!(:old_certs) { inspect.certificates(layout.cacert) }
    let!(:old_crl_count) { extend.crl_number(inspect.crls(layout.cacrl).first) }

    before { write_fake(fake) }

    after { FileUtils.rm_rf(layout.dir) }

    it 'runs the subcommand with the TTL, verifies the result, and reports like the library does' do
      result = with_env(layout) { described_class.extend(layout.settings, ttl: '15y', bin: fake) }
      expect(File.read(log)).to eq('--ttl 15y')
      expect(result['layout']).to eq('intermediate')
      expect(result['certificates'].map { |c| c['serial'] }).to eq(old_certs.map { |c| c.serial.to_s })
      expect(result['certificates'].map { |c| c['self_signed'] }).to eq([false, true])
      expect(result['certificates'].map { |c| c['key_file'] }).to eq([layout.cakey, layout.rootkey])
      fresh = inspect.certificates(layout.cacert)
      expect(fresh.map(&:not_after)).to all(be > old_certs.first.not_after)
      expect(result['not_after']).to eq(fresh.first.not_after.utc.iso8601)
      expect(result['output']).to start_with('Extended the CA certificate')
    end

    it 'passes --force through' do
      with_env(layout) { described_class.extend(layout.settings, ttl: '400d', force: true, bin: fake) }
      expect(File.read(log)).to eq('--ttl 400d --force')
    end

    it 'takes its own backups of every affected file before calling the subcommand' do
      result = with_env(layout) { described_class.extend(layout.settings, ttl: '15y', bin: fake) }
      expect(result['backups'].length).to eq(5)
      expect(result['backups']).to all(satisfy { |b| File.exist?(b) })
      restored = result['backups'].find { |b| b.start_with?(layout.cacert) }
      expect(inspect.certificates(restored).map(&:not_after)).to eq(old_certs.map(&:not_after))
    end

    it 'lists the files that changed and leaves unexpired CRLs alone by default' do
      result = with_env(layout) { described_class.extend(layout.settings, ttl: '15y', bin: fake) }
      expect(result['written']).to contain_exactly(layout.cacert, layout.localcacert)
      expect(result['crl_files'].values.flat_map { |d| d['items'] }.map { |i| i['resigned'] }).to all(be(false))
      expect(File.read(layout.localcacert)).to eq(File.read(layout.cacert))
    end

    it 're-signs every CRL itself when asked for all, keeping revoked entries' do
      result = with_env(layout) { described_class.extend(layout.settings, ttl: '15y', crls: :all, bin: fake) }
      expect(result['written']).to include(layout.cacrl, layout.hostcrl, layout.infra_crl)
      items = result['crl_files'][layout.cacrl]['items']
      expect(items.map { |i| i['resigned'] }).to all(be(true))
      expect(items.first['revoked_count']).to eq(1)
      expect(extend.crl_number(inspect.crls(layout.cacrl).first)).to eq(old_crl_count + 1)
      expect(File.read(layout.hostcrl)).to eq(File.read(layout.cacrl))
    end

    it 'refuses an external CA before the subcommand runs' do
      external = CaFixtures.intermediate_ca(keep_root_key: false)
      expect { with_env(external) { described_class.extend(external.settings, ttl: '15y', bin: fake) } }.to raise_error(extend::Error, %r{No private key on disk})
      expect(File.exist?(log)).to be(false)
      FileUtils.rm_rf(external.dir)
    end

    it 'raises when the subcommand fails, with its output' do
      write_fake(fake, fail_with: 'CA is online; pass --force')
      expect { with_env(layout) { described_class.extend(layout.settings, ttl: '15y', bin: fake) } }.to raise_error(extend::Error, %r{ca extend failed: CA is online})
    end

    it 'raises when the subcommand does not move the expiry' do
      File.write(fake, "#!/usr/bin/env ruby\nputs 'nothing to do'\n")
      expect { with_env(layout) { described_class.extend(layout.settings, ttl: '15y', bin: fake) } }.to raise_error(extend::Error, %r{did not move the expiry})
    end
  end
end
