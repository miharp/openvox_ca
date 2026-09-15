# frozen_string_literal: true

require 'openssl'
require 'fileutils'
require 'time'
require_relative 'inspect'

module PuppetX
  module OpenvoxCa
    # Re-signs an OpenVox CA certificate bundle in place so that it gets a new
    # validity period while keeping the same keys, subjects, serials, and
    # extensions. Every certificate the CA ever issued stays valid because the
    # signing keys do not change. Handles the single self-signed layout and the
    # root plus intermediate bundle. Pure Ruby with no Puppet dependency.
    module Extend
      DAY = 60 * 60 * 24
      TTL_FORMAT = %r{\A(\d+)([ydhms])?\z}.freeze
      TTL_UNITMAP = { 'y' => 365 * DAY, 'd' => DAY, 'h' => 60 * 60, 'm' => 60, 's' => 1 }.freeze
      DIGEST = 'SHA256'
      MAX_CERTS = 2

      class Error < StandardError; end

      module_function

      # Seconds for a duration in the same format the CA gem accepts: a number
      # with an optional y, d, h, m, or s suffix, defaulting to seconds.
      def parse_ttl(value)
        return value if value.is_a?(Integer) && value.positive?

        match = TTL_FORMAT.match(value.to_s)
        raise Error, "Invalid TTL #{value.inspect}: expected a number with an optional y, d, h, m, or s suffix" unless match

        seconds = match[1].to_i * TTL_UNITMAP[match[2] || 's']
        raise Error, "Invalid TTL #{value.inspect}: must be positive" unless seconds.positive?

        seconds
      end

      # Loads the bundle and keys and works out which key signs which
      # certificate. Returns an array of entries in bundle order, each with
      # :cert, :key, :key_path, and :issuer (another entry, itself for a
      # self-signed certificate). Raises Error for anything this module
      # refuses to extend.
      def analyse(settings)
        cacert = settings['cacert']
        raise Error, "CA certificate bundle not found: #{cacert}" unless cacert && File.exist?(cacert)

        certs = Inspect.certificates(cacert)
        raise Error, "No certificates found in #{cacert}" if certs.empty?
        raise Error, "#{cacert} holds #{certs.length} certificates; only bundles of one or two are supported" if certs.length > MAX_CERTS

        keys = Inspect.keys([settings['cakey'], settings['rootkey']])
        entries = certs.map do |cert|
          key_path = Inspect.matching_key(cert, keys)
          { cert: cert, key_path: key_path, key: keys[key_path] }
        end

        external = entries.reject { |e| e[:key] }.map { |e| e[:cert].subject.to_s }
        raise Error, "No private key on disk for #{external.join(', ')}; an externally issued CA must be extended by its issuer and imported with `puppetserver ca import`" unless external.empty?

        entries.each do |entry|
          entry[:issuer] = entries.find { |candidate| issued?(entry[:cert], candidate[:cert]) }
          raise Error, "Cannot find the issuer of #{entry[:cert].subject} in #{cacert}" unless entry[:issuer]
        end
        entries
      end

      def issued?(cert, candidate)
        cert.issuer.eql?(candidate.subject) && cert.verify(candidate.public_key)
      rescue OpenSSL::X509::CertificateError
        false
      end

      # A copy of `cert` with new validity dates, signed by `signing_key`.
      def resign_certificate(cert, signing_key, not_before:, not_after:)
        fresh = OpenSSL::X509::Certificate.new
        fresh.version = cert.version
        fresh.serial = cert.serial
        fresh.subject = cert.subject
        fresh.issuer = cert.issuer
        fresh.public_key = cert.public_key
        fresh.not_before = not_before
        fresh.not_after = not_after
        cert.extensions.each { |ext| fresh.add_extension(ext) }
        fresh.sign(signing_key, OpenSSL::Digest.new(DIGEST))
      end

      def crl_number(crl)
        ext = crl.extensions.find { |e| e.oid == 'crlNumber' }
        return 0 unless ext

        OpenSSL::ASN1.decode(ext.value_der).value.to_i
      rescue NoMethodError
        ext.value.to_i
      end

      # A copy of `crl` with fresh update times, the same revoked entries, and
      # crlNumber incremented, signed by `signing_key`.
      def resign_crl(crl, signing_key, now:, next_update:)
        fresh = OpenSSL::X509::CRL.new
        fresh.version = crl.version
        fresh.issuer = crl.issuer
        fresh.last_update = now - DAY
        fresh.next_update = next_update
        crl.revoked.each { |entry| fresh.add_revoked(entry) }
        crl.extensions.each do |ext|
          next if ext.oid == 'crlNumber'

          fresh.add_extension(ext)
        end
        fresh.add_extension(OpenSSL::X509::Extension.new('crlNumber', OpenSSL::ASN1::Integer(crl_number(crl) + 1)))
        fresh.sign(signing_key, OpenSSL::Digest.new(DIGEST))
      end

      # Works out the new bundle and CRLs without writing anything.
      #
      # `crls` is :expired to re-sign only CRLs whose next_update has passed,
      # :all to re-sign every CRL the CA owns, or :none.
      #
      # Returns a hash with 'layout', 'not_before', 'not_after', 'certificates'
      # (one summary per certificate), 'bundle_pem', and 'crl_files' mapping
      # each CRL file path to { 'pem' => new content, 'items' => summaries }.
      def compute(settings, ttl_seconds:, crls: :expired, now: Time.now)
        entries = analyse(settings)
        not_before = now - DAY
        not_after = now + ttl_seconds

        fresh_by_entry = {}
        entries.each do |entry|
          fresh_by_entry[entry] = resign_certificate(entry[:cert], entry[:issuer][:key], not_before: not_before, not_after: not_after)
        end
        fresh_certs = entries.map { |e| fresh_by_entry[e] }
        verify_chain!(fresh_certs)

        certificates = entries.map do |entry|
          {
            'subject' => entry[:cert].subject.to_s,
            'serial' => entry[:cert].serial.to_s,
            'self_signed' => entry[:issuer].equal?(entry),
            'signed_by' => entry[:issuer][:cert].subject.to_s,
            'key_file' => entry[:key_path],
            'old_not_after' => entry[:cert].not_after.utc.iso8601,
            'new_not_after' => not_after.utc.iso8601,
          }
        end

        crl_files = crl_paths(settings).to_h do |path|
          [path, compute_crl_file(path, entries, crls, now, not_after)]
        end

        {
          'layout' => (entries.length == 1) ? 'single' : 'intermediate',
          'not_before' => not_before.utc.iso8601,
          'not_after' => not_after.utc.iso8601,
          'certificates' => certificates,
          'bundle_pem' => fresh_certs.map(&:to_pem).join,
          'crl_files' => crl_files,
        }
      end

      def crl_paths(settings)
        paths = [settings['cacrl']]
        paths << File.join(settings['cadir'], 'infra_crl.pem') if settings['cadir']
        paths.compact.uniq.select { |p| File.exist?(p) }
      end

      def compute_crl_file(path, entries, mode, now, next_update)
        items = []
        pems = Inspect.crls(path).map do |crl|
          owner = entries.find { |e| crl.issuer.eql?(e[:cert].subject) && crl.verify(e[:cert].public_key) }
          raise Error, "CRL in #{path} issued by #{crl.issuer} does not belong to this CA" unless owner

          expired = crl.next_update < now
          resign = mode == :all || (mode == :expired && expired)
          fresh = resign ? resign_crl(crl, owner[:key], now: now, next_update: next_update) : crl
          items << {
            'issuer' => crl.issuer.to_s,
            'revoked_count' => crl.revoked.length,
            'old_next_update' => crl.next_update.utc.iso8601,
            'new_next_update' => fresh.next_update.utc.iso8601,
            'resigned' => resign,
          }
          fresh.to_pem
        end
        { 'pem' => pems.join, 'items' => items }
      end

      # Raises unless every certificate verifies against the bundle's own roots.
      def verify_chain!(certs)
        roots, others = certs.partition { |c| c.subject.eql?(c.issuer) }
        roots.each do |root|
          raise Error, "Re-signed root #{root.subject} does not verify with its own key" unless root.verify(root.public_key)
        end
        store = OpenSSL::X509::Store.new
        roots.each { |root| store.add_cert(root) }
        others.each do |cert|
          raise Error, "Re-signed #{cert.subject} does not verify against the root: #{store.error_string}" unless store.verify(cert)
        end
      end

      # The files `apply` would write for a computed result: path => content.
      def planned_writes(settings, result)
        writes = { settings['cacert'] => result['bundle_pem'] }
        writes[settings['localcacert']] = result['bundle_pem'] if settings['localcacert']
        result['crl_files'].each { |path, data| writes[path] = data['pem'] }
        writes[settings['hostcrl']] = result['crl_files'][settings['cacrl']]['pem'] if settings['hostcrl'] && result['crl_files'][settings['cacrl']]
        writes
      end

      # Backs up and replaces every affected file. Returns the paths written
      # and the backups made. Existing mode and ownership are preserved.
      def apply(settings, result, now: Time.now)
        stamp = now.utc.strftime('%Y%m%dT%H%M%SZ')
        written = []
        backups = []
        planned_writes(settings, result).each do |path, content|
          if File.exist?(path)
            backup = "#{path}.#{stamp}.bak"
            FileUtils.cp(path, backup, preserve: true)
            backups << backup
          end
          write_atomically(path, content)
          written << path
        end
        { 'written' => written, 'backups' => backups }
      end

      def write_atomically(path, content)
        FileUtils.mkdir_p(File.dirname(path))
        stat = File.exist?(path) ? File.stat(path) : nil
        tmp = "#{path}.tmp#{Process.pid}"
        File.write(tmp, content)
        if stat
          File.chmod(stat.mode & 0o7777, tmp)
          begin
            File.chown(stat.uid, stat.gid, tmp)
          rescue Errno::EPERM
            nil
          end
        else
          File.chmod(0o644, tmp)
        end
        File.rename(tmp, path)
      end
    end
  end
end
