# frozen_string_literal: true

require 'openssl'
require 'time'

module PuppetX
  module OpenvoxCa
    # Read-only inspection of the certificate files an OpenVox deployment
    # carries: CA bundles, CRLs, and host certificates. Shared by the check
    # tasks and used directly by the specs. Pure Ruby with no Puppet dependency.
    module Inspect
      DAY = 60 * 60 * 24
      CERT_PATTERN = %r{-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----}m.freeze
      CRL_PATTERN = %r{-----BEGIN X509 CRL-----.*?-----END X509 CRL-----}m.freeze

      module_function

      # Every certificate in a PEM file, in file order. Raises Malformed when
      # the file holds none, so an empty or truncated file is never reported
      # as healthy or copied over a good one.
      def certificates(path)
        certs = File.read(path).scan(CERT_PATTERN).map { |pem| OpenSSL::X509::Certificate.new(pem) }
        raise Malformed, "#{path} holds no certificate" if certs.empty?

        certs
      end

      # Every CRL in a PEM file, in file order. Raises Malformed when the file
      # holds none.
      def crls(path)
        crls = File.read(path).scan(CRL_PATTERN).map { |pem| OpenSSL::X509::CRL.new(pem) }
        raise Malformed, "#{path} holds no CRL" if crls.empty?

        crls
      end

      # Raised for a file that exists but holds nothing parseable.
      class Malformed < StandardError; end

      # Private keys from the given paths, skipping paths that do not exist.
      # Returns a hash of path => key.
      def keys(paths)
        paths.compact.select { |p| File.exist?(p) }.to_h { |p| [p, OpenSSL::PKey.read(File.read(p))] }
      end

      # The path of the key whose public half matches the certificate, or nil.
      def matching_key(cert, keys)
        public_der = cert.public_key.to_der
        keys.find { |_path, key| key.public_key.to_der == public_der }&.first
      end

      def days_left(time, now = Time.now)
        ((time - now) / DAY).floor
      end

      def status_for(days, warn_days)
        if days.negative?
          'expired'
        elsif days < warn_days
          'warn'
        else
          'ok'
        end
      end

      # One report item for a certificate. Key fields are included only when
      # keys were given to match against, which is the case for CA certificates.
      def certificate_item(cert, kind:, file:, warn_days:, keys: nil, now: Time.now)
        days = days_left(cert.not_after, now)
        item = {
          'kind' => kind,
          'file' => file,
          'subject' => cert.subject.to_s,
          'issuer' => cert.issuer.to_s,
          'serial' => cert.serial.to_s,
          'not_before' => cert.not_before.utc.iso8601,
          'not_after' => cert.not_after.utc.iso8601,
          'days_left' => days,
          'status' => status_for(days, warn_days),
          'self_signed' => cert.subject.eql?(cert.issuer),
        }
        return item if keys.nil?

        key = matching_key(cert, keys)
        item.merge('key_present' => !key.nil?, 'key_file' => key)
      end

      # One report item for a CRL.
      def crl_item(crl, file:, warn_days:, now: Time.now)
        days = days_left(crl.next_update, now)
        {
          'kind' => 'crl',
          'file' => file,
          'issuer' => crl.issuer.to_s,
          'last_update' => crl.last_update.utc.iso8601,
          'next_update' => crl.next_update.utc.iso8601,
          'days_left' => days,
          'status' => status_for(days, warn_days),
          'revoked_count' => crl.revoked.length,
        }
      end

      # Items for every certificate in a bundle file.
      def bundle_items(path, kind:, warn_days:, keys: nil, now: Time.now)
        return [] unless File.exist?(path)

        certificates(path).map { |c| certificate_item(c, kind: kind, file: path, warn_days: warn_days, keys: keys, now: now) }
      end

      # Items for every CRL in a CRL file.
      def crl_items(path, warn_days:, now: Time.now)
        return [] unless File.exist?(path)

        crls(path).map { |c| crl_item(c, file: path, warn_days: warn_days, now: now) }
      end

      # The worst status across a list of items: expired beats warn beats ok.
      def overall_status(items)
        statuses = items.map { |i| i['status'] }
        if statuses.include?('expired')
          'expired'
        elsif statuses.include?('warn')
          'warn'
        else
          'ok'
        end
      end

      # One report item for a certificate the CA issued, read from the signed
      # directory. The certname is the file name without its extension, which
      # is how `puppetserver ca sign` files them.
      def issued_item(cert, file:, warn_days:, revoked_serials:, now: Time.now)
        certificate_item(cert, kind: 'issued_cert', file: file, warn_days: warn_days, now: now).merge(
          'certname' => File.basename(file, '.pem'),
          'revoked' => revoked_serials.include?(cert.serial.to_s),
        )
      end

      # Items for every certificate in the CA's signed directory, in name order.
      def issued_items(signeddir, warn_days:, revoked_serials: [], now: Time.now)
        return [] unless signeddir && File.directory?(signeddir)

        Dir.glob(File.join(signeddir, '*.pem')).sort.flat_map do |file|
          certificates(file).map { |c| issued_item(c, file: file, warn_days: warn_days, revoked_serials: revoked_serials, now: now) }
        end
      end

      # Serials revoked by any CRL in the file, as strings, for matching
      # against `certificate_item` serials.
      def revoked_serials(path)
        return [] unless path && File.exist?(path)

        crls(path).flat_map { |crl| crl.revoked.map { |entry| entry.serial.to_s } }
      end

      # Counts by status over issued-certificate items.
      def issued_summary(items)
        {
          'total' => items.length,
          'ok' => items.count { |i| i['status'] == 'ok' },
          'warn' => items.count { |i| i['status'] == 'warn' },
          'expired' => items.count { |i| i['status'] == 'expired' },
          'revoked' => items.count { |i| i['revoked'] },
        }
      end

      # Full report for a CA host. `settings` holds the resolved Puppet settings
      # (cacert, cakey, rootkey, cacrl, cadir, signeddir, localcacert, hostcert,
      # hostcrl).
      #
      # `issued` controls the audit of certificates the CA has issued, read
      # from `signeddir`: :due lists only those expiring within the window or
      # already expired, :all lists every one, :none skips the directory. The
      # summary counts under 'issued' always cover the whole directory. The
      # report's overall status covers only the CA's own files, because an
      # expiring agent certificate is not a reason to extend the CA.
      def ca_report(settings, warn_days: 90, issued: :due, now: Time.now)
        require_files!(settings, %w[cacert])
        keys = keys([settings['cakey'], settings['rootkey']])
        items = []
        items.concat(bundle_items(settings['cacert'], kind: 'ca_cert', warn_days: warn_days, keys: keys, now: now))
        items.concat(crl_items(settings['cacrl'], warn_days: warn_days, now: now))
        infra_crl = File.join(settings['cadir'].to_s, 'infra_crl.pem')
        items.concat(crl_items(infra_crl, warn_days: warn_days, now: now)) if settings['cadir']
        items.concat(host_items(settings, warn_days: warn_days, now: now))
        external = items.select { |i| i['kind'] == 'ca_cert' && i['key_present'] == false }.map { |i| i['subject'] }
        status = overall_status(items)

        summary = nil
        unless issued.to_sym == :none
          all_issued = issued_items(settings['signeddir'], warn_days: warn_days, revoked_serials: revoked_serials(settings['cacrl']), now: now)
          summary = issued_summary(all_issued)
          items.concat((issued.to_sym == :all) ? all_issued : all_issued.reject { |i| i['status'] == 'ok' })
        end

        {
          'status' => status,
          'warn_days' => warn_days,
          'checked_at' => now.utc.iso8601,
          'layout' => layout_for(items),
          'external_ca_subjects' => external,
          'issued' => summary,
          'items' => items,
        }
      end

      # Report for a host that is not the CA: its own certificate, its copy of
      # the CA bundle, and its copy of the CRL.
      def host_report(settings, warn_days: 90, now: Time.now)
        items = host_items(settings, warn_days: warn_days, now: now)
        {
          'status' => overall_status(items),
          'warn_days' => warn_days,
          'checked_at' => now.utc.iso8601,
          'items' => items,
        }
      end

      # Raises when the files a report needs are absent, which usually means
      # the settings were resolved as the wrong user: a non-root
      # `puppet config print` points at that user's own confdir.
      def require_files!(settings, names)
        missing = names.map { |n| settings[n] }.compact.reject { |p| File.exist?(p) }
        return if missing.empty?

        raise MissingFiles, "Certificate files not found: #{missing.join(', ')}. If they exist, run the task with enough privilege to see them (for example --run-as root)."
      end

      class MissingFiles < StandardError; end

      def host_items(settings, warn_days:, now:)
        require_files!(settings, %w[hostcert localcacert])
        items = []
        items.concat(bundle_items(settings['hostcert'], kind: 'host_cert', warn_days: warn_days, now: now))
        items.concat(bundle_items(settings['localcacert'], kind: 'local_ca_copy', warn_days: warn_days, now: now))
        items.concat(crl_items(settings['hostcrl'], warn_days: warn_days, now: now))
        items
      end

      def layout_for(items)
        count = items.count { |i| i['kind'] == 'ca_cert' }
        case count
        when 0 then 'none'
        when 1 then 'single'
        when 2 then 'intermediate'
        else 'unsupported'
        end
      end
    end
  end
end
