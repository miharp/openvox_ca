# @summary Re-sign the CA certificate in place on the CA host and restart the services that use it.
#
# Stops OpenVox Server, re-signs the CA bundle with the same keys and a new
# validity period, refreshes OpenVoxDB's copies if it runs on the same host,
# starts everything again, and prints the expiry before and after. Every file
# the plan replaces is backed up next to the original first.
#
# Agents keep working with their old copy of the CA certificate until it
# expires, because the signing key has not changed. Distribute the new bundle
# before that happens.
#
# @param ca The CA host. Exactly one target.
# @param ttl New lifetime for the CA certificate, in the CA gem's format.
# @param crls Which CRLs to re-sign: only expired ones, all, or none.
# @param regen_primary_cert Also replace the CA host's own certificate, for when it has expired too.
# @param dns_alt_names Subject alternative names for the regenerated host certificate.
# @param restart_puppetdb Refresh and restart OpenVoxDB if it is installed on the CA host.
# @param dry_run Report what would change without stopping anything or writing any file.
# @param force Extend even when nothing is due to expire within warn_days.
# @param warn_days The window used to decide whether anything is due.
# @return [Hash] `before` and `after` hold the CA reports, `extend` the task result.
plan openvox_ca::extend (
  TargetSpec                  $ca,
  Pattern[/\A\d+[ydhms]?\z/]  $ttl                = '15y',
  Enum[expired, all, none]    $crls               = 'expired',
  Boolean                     $regen_primary_cert = false,
  Optional[Array[String[1]]]  $dns_alt_names      = undef,
  Boolean                     $restart_puppetdb   = true,
  Boolean                     $dry_run            = false,
  Boolean                     $force              = false,
  Integer[0]                  $warn_days          = 90,
) {
  $ca_targets = get_targets($ca)
  if $ca_targets.length != 1 {
    fail_plan("Expected exactly one CA target, got ${ca_targets.length}", 'openvox_ca/bad-ca-target')
  }
  $target = $ca_targets[0]

  $before = run_task('openvox_ca::check_ca', $target, 'warn_days' => $warn_days).first.value
  $ca_items = $before['items'].filter |$i| { $i['kind'] == 'ca_cert' }
  out::message("CA on ${target.name}: layout ${before['layout']}, status ${before['status']}")
  $ca_items.each |$i| {
    out::message(sprintf('  %-8s expires %s (%d days)  %s', $i['status'], $i['not_after'][0, 10], $i['days_left'], $i['subject']))
  }

  unless $before['external_ca_subjects'].empty {
    fail_plan("Externally issued CA: no private key on disk for ${before['external_ca_subjects'].join(', ')}", 'openvox_ca/external-ca')
  }
  if $before['status'] == 'ok' and !$force and !$dry_run {
    fail_plan("Nothing expires within ${warn_days} days. Pass force=true to extend anyway.", 'openvox_ca/nothing-due')
  }

  if $dry_run {
    $planned = run_task('openvox_ca::extend_ca', $target, 'ttl' => $ttl, 'crls' => $crls, 'dry_run' => true).first.value
    out::message("Dry run: would re-sign ${planned['certificates'].length} certificate(s) to expire ${planned['not_after'][0, 10]}")
    $planned['planned_writes'].each |$f| { out::message("  would write ${f}") }
    return({ 'before' => $before, 'extend' => $planned, 'after' => undef })
  }

  out::message('Stopping puppetserver')
  run_command('systemctl stop puppetserver', $target)

  $extend = run_task('openvox_ca::extend_ca', $target, 'ttl' => $ttl, 'crls' => $crls).first.value
  $extend['certificates'].each |$c| {
    out::message("  re-signed ${c['subject']}: ${c['old_not_after'][0, 10]} -> ${c['new_not_after'][0, 10]}")
  }
  $extend['crls'].filter |$c| { $c['resigned'] }.each |$c| {
    out::message("  re-signed CRL from ${c['issuer']} in ${c['file']}")
  }
  $extend['backups'].each |$b| { out::message("  backup ${b}") }

  if $regen_primary_cert {
    $regen = run_task('openvox_ca::regen_primary_cert', $target, 'dns_alt_names' => $dns_alt_names).first.value
    out::message("  regenerated ${regen['certname']} certificate, expires ${regen['not_after'][0, 10]}")
    unless $regen['old_alt_names'].empty {
      out::message("  old certificate had alt names: ${regen['old_alt_names'].join(', ')}")
    }
  }

  if $restart_puppetdb {
    $pdb = run_task('openvox_ca::refresh_puppetdb_ssl', $target).first.value
    if $pdb['present'] {
      out::message('Refreshed OpenVoxDB SSL files, restarting puppetdb')
      run_command('systemctl restart puppetdb', $target)
    }
  }

  out::message('Starting puppetserver')
  run_command('systemctl start puppetserver', $target)
  $up = ctrl::do_until({ 'limit' => 36, 'interval' => 5 }) || {
    run_command('curl -sSf --insecure https://127.0.0.1:8140/status/v1/simple', $target, '_catch_errors' => true).ok
  }
  unless $up {
    fail_plan('puppetserver did not answer on port 8140 within three minutes after the restart', 'openvox_ca/server-not-up')
  }

  $after = run_task('openvox_ca::check_ca', $target, 'warn_days' => $warn_days).first.value
  out::message("CA on ${target.name} after extend: status ${after['status']}")
  $after['items'].filter |$i| { $i['kind'] == 'ca_cert' }.each |$i| {
    out::message(sprintf('  %-8s expires %s (%d days)  %s', $i['status'], $i['not_after'][0, 10], $i['days_left'], $i['subject']))
  }

  return({ 'before' => $before, 'extend' => $extend, 'after' => $after })
}
