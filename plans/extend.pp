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
# The re-signing itself is done by `puppetserver ca extend` when the CA CLI on
# the host has that subcommand, and by the module's own implementation
# otherwise. Pass `implementation` to force one or the other.
#
# @param ca The CA host. Exactly one target.
# @param ttl New lifetime for the CA certificate, in the CA gem's format.
# @param implementation `auto` prefers `puppetserver ca extend` when present, `gem` requires it, `library` never uses it.
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
  Enum[auto, gem, library]    $implementation     = 'auto',
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

  $before = run_task('openvox_ca::check_ca', $target, 'warn_days' => $warn_days, 'issued' => 'none').first.value
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
    $planned = run_task('openvox_ca::extend_ca', $target, 'ttl' => $ttl, 'crls' => $crls, 'implementation' => $implementation, 'dry_run' => true).first.value
    out::message("Dry run: would re-sign ${planned['certificates'].length} certificate(s) to expire ${planned['not_after'][0, 10]} using the ${planned['implementation']}")
    $planned['planned_writes'].each |$f| { out::message("  would write ${f}") }
    return({ 'before' => $before, 'extend' => $planned, 'after' => undef })
  }

  out::message('Stopping puppetserver')
  run_command('systemctl stop puppetserver', $target)

  # Everything between the stop and the start is run with errors caught, so
  # that whatever fails, puppetserver is started again before the plan
  # fails. Each step runs only if the previous ones succeeded. Every file the
  # tasks write is backed up first, so the CA directory is either untouched
  # or recoverable from the backups they print.
  $extend_result = run_task('openvox_ca::extend_ca', $target, 'ttl' => $ttl, 'crls' => $crls, 'implementation' => $implementation, '_catch_errors' => true).first
  if $extend_result.ok {
    $extend = $extend_result.value
    if $extend['implementation'] == 'gem' {
      out::message('  re-signed with puppetserver ca extend')
    }
    $extend['certificates'].each |$c| {
      out::message("  re-signed ${c['subject']}: ${c['old_not_after'][0, 10]} -> ${c['new_not_after'][0, 10]}")
    }
    $extend['crls'].filter |$c| { $c['resigned'] }.each |$c| {
      out::message("  re-signed CRL from ${c['issuer']} in ${c['file']}")
    }
    $extend['backups'].each |$b| { out::message("  backup ${b}") }
  } else {
    $extend = undef
  }

  $regen_result = if $extend_result.ok and $regen_primary_cert {
    run_task('openvox_ca::regen_primary_cert', $target, 'dns_alt_names' => $dns_alt_names, '_catch_errors' => true).first
  } else {
    undef
  }
  if $regen_result =~ NotUndef and $regen_result.ok {
    $regen = $regen_result.value
    out::message("  regenerated ${regen['certname']} certificate, expires ${regen['not_after'][0, 10]}")
    unless $regen['old_alt_names'].empty {
      out::message("  old certificate had alt names: ${regen['old_alt_names'].join(', ')}")
    }
  }

  $pdb_result = if $extend_result.ok and ($regen_result =~ Undef or $regen_result.ok) and $restart_puppetdb {
    run_task('openvox_ca::refresh_puppetdb_ssl', $target, '_catch_errors' => true).first
  } else {
    undef
  }
  $pdb_restart_result = if $pdb_result =~ NotUndef and $pdb_result.ok and $pdb_result.value['present'] {
    out::message('Refreshed OpenVoxDB SSL files, restarting puppetdb')
    run_command('systemctl restart puppetdb', $target, '_catch_errors' => true).first
  } else {
    undef
  }

  $failed = [$extend_result, $regen_result, $pdb_result, $pdb_restart_result].filter |$r| { $r =~ NotUndef and !$r.ok }

  out::message('Starting puppetserver')
  run_command('systemctl start puppetserver', $target, '_catch_errors' => !$failed.empty)
  unless $failed.empty {
    $error = $failed[0].error
    out::message("Failed: ${error.message}")
    fail_plan($error.message, $error.kind, $error.details)
  }
  $up = ctrl::do_until({ 'limit' => 36, 'interval' => 5 }) || {
    run_command('curl -sSf --insecure https://127.0.0.1:8140/status/v1/simple', $target, '_catch_errors' => true).ok
  }
  unless $up {
    fail_plan('puppetserver did not answer on port 8140 within three minutes after the restart', 'openvox_ca/server-not-up')
  }

  $after = run_task('openvox_ca::check_ca', $target, 'warn_days' => $warn_days, 'issued' => 'none').first.value
  out::message("CA on ${target.name} after extend: status ${after['status']}")
  $after['items'].filter |$i| { $i['kind'] == 'ca_cert' }.each |$i| {
    out::message(sprintf('  %-8s expires %s (%d days)  %s', $i['status'], $i['not_after'][0, 10], $i['days_left'], $i['subject']))
  }

  return({ 'before' => $before, 'extend' => $extend, 'after' => $after })
}
