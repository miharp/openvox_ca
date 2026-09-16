# frozen_string_literal: true

require 'open3'
require 'time'
require_relative 'inspect'
require_relative 'extend'
require_relative 'service'

module PuppetX
  module OpenvoxCa
    # Wraps the `puppetserver ca extend` subcommand proposed for the OpenVox CA
    # gem in OpenVoxProject/openvoxserver-ca#56. When the subcommand is
    # present the task prefers it over the module's own re-signing library, so
    # the deployment's own tooling does the cryptography and the module only
    # orchestrates. The report has the same shape either way.
    #
    # The proposed interface is `puppetserver ca extend [--ttl TTL] [--force]`:
    # it re-signs every certificate the CA owns with the same keys, re-signs
    # expired CRLs, backs its files up, and writes the bundle to `cacert` and
    # `localcacert`. Until the subcommand ships this wrapper is exercised only
    # against a stand-in in the unit specs.
    module CaCli
      module_function

      # True when the CA CLI on this host lists `extend` among its actions.
      # The general usage is the only reliable signal: `puppetserver ca
      # extend --help` on a CLI without the action prints "Unknown action"
      # followed by the whole usage, which mentions `--ttl` for other actions,
      # and still exits zero.
      def extend_available?(bin: Service.puppetserver_bin)
        return false unless bin

        out, err, status = Open3.capture3(bin, 'ca', '--help')
        return false unless status.success?

        text = out + err
        !text.match?(%r{Unknown action}i) && text.lines.any? { |l| l.match?(%r{\A\s+extend(\s|\z)}) }
      rescue SystemCallError
        false
      end

      # Runs the subcommand and reads the result back. Applies the same
      # refusals as the library first, so an external CA or an oversized
      # bundle never reaches the gem. `ttl` is the duration string the gem
      # accepts. Returns the keys the extend task reports: 'layout',
      # 'not_before', 'not_after', 'certificates', 'crl_files', 'written',
      # 'backups', and 'output'.
      def extend(settings, ttl:, crls: :expired, force: false, now: Time.now, bin: Service.puppetserver_bin)
        raise Extend::Error, 'puppetserver executable not found' unless bin

        before = Extend.analyse(settings)
        old_files = snapshot(settings)
        old_crls = Extend.crl_paths(settings).to_h { |p| [p, Inspect.crls(p)] }
        backups = Extend.backup(Extend.affected_paths(settings), now: now)

        cmd = [bin, 'ca', 'extend', '--ttl', ttl.to_s]
        cmd << '--force' if force
        out, err, status = Open3.capture3(*cmd)
        raise Extend::Error, "puppetserver ca extend failed: #{(out + err).strip}" unless status.success?

        after = Extend.analyse(settings)
        certificates = verify_resigned!(before, after)
        not_after = after.first[:cert].not_after

        resign_crls_all!(settings, after, now, not_after) if crls == :all
        sync_copies!(settings)

        {
          'layout' => (after.length == 1) ? 'single' : 'intermediate',
          'not_before' => after.first[:cert].not_before.utc.iso8601,
          'not_after' => not_after.utc.iso8601,
          'certificates' => certificates,
          'crl_files' => crl_report(old_crls),
          'written' => changed_files(old_files, snapshot(settings)),
          'backups' => backups,
          'output' => out.strip,
        }
      end

      # Raises unless the gem re-signed every certificate with the same serial
      # and public key and a later expiry. Returns the per-certificate summary.
      def verify_resigned!(before, after)
        raise Extend::Error, "puppetserver ca extend changed the number of certificates in the bundle from #{before.length} to #{after.length}" unless before.length == after.length

        before.zip(after).map do |old, fresh|
          oc = old[:cert]
          nc = fresh[:cert]
          raise Extend::Error, "puppetserver ca extend replaced #{oc.subject} with a different certificate" unless oc.serial == nc.serial && oc.public_key.to_der == nc.public_key.to_der
          raise Extend::Error, "puppetserver ca extend did not move the expiry of #{oc.subject} (still #{oc.not_after.utc.iso8601})" unless nc.not_after > oc.not_after

          {
            'subject' => nc.subject.to_s,
            'serial' => nc.serial.to_s,
            'self_signed' => fresh[:issuer].equal?(fresh),
            'signed_by' => fresh[:issuer][:cert].subject.to_s,
            'key_file' => fresh[:key_path],
            'old_not_after' => oc.not_after.utc.iso8601,
            'new_not_after' => nc.not_after.utc.iso8601,
          }
        end
      end

      # The gem only re-signs expired CRLs; `crls=all` re-signs the rest here.
      def resign_crls_all!(settings, entries, now, next_update)
        Extend.crl_paths(settings).each do |path|
          data = Extend.compute_crl_file(path, entries, :all, now, next_update)
          Extend.write_atomically(path, data['pem'])
        end
      end

      # Makes sure the host's own copies match what the CA now holds, in case
      # the gem writes only the CA directory.
      def sync_copies!(settings)
        { 'localcacert' => 'cacert', 'hostcrl' => 'cacrl' }.each do |copy, source|
          next unless settings[copy] && settings[source] && File.exist?(settings[source])

          content = File.read(settings[source])
          next if File.exist?(settings[copy]) && File.read(settings[copy]) == content

          Extend.write_atomically(settings[copy], content)
        end
      end

      def crl_report(old_crls)
        old_crls.to_h do |path, crls|
          items = Inspect.crls(path).zip(crls).map do |fresh, old|
            {
              'issuer' => fresh.issuer.to_s,
              'revoked_count' => fresh.revoked.length,
              'old_next_update' => (old || fresh).next_update.utc.iso8601,
              'new_next_update' => fresh.next_update.utc.iso8601,
              'resigned' => old.nil? || old.to_der != fresh.to_der,
            }
          end
          [path, { 'items' => items }]
        end
      end

      def snapshot(settings)
        paths = %w[cacert localcacert cacrl hostcrl].map { |n| settings[n] } + Extend.crl_paths(settings)
        paths.compact.uniq.to_h { |p| [p, File.exist?(p) ? File.read(p) : nil] }
      end

      def changed_files(before, after)
        after.reject { |path, content| before[path] == content }.keys
      end
    end
  end
end
