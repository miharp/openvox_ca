# @summary Get the CA host's current CA bundle onto other hosts.
#
# Two strategies. `refetch` (the default) moves each host's copy of the CA
# bundle and CRL aside and runs the agent once in no-op mode so it fetches
# fresh copies from the server; agents fetch the bundle without needing a
# valid one, so this works after the old copy has expired. `upload` reads the
# bundle and CRL from the CA host and writes them to each target directly,
# for hosts that cannot reach the server or should not run the agent.
#
# On a healthy deployment neither is needed: agents refresh their CA bundle
# from the server every `ca_refresh_interval` (one day by default).
#
# @param ca The CA host. Exactly one target.
# @param targets The hosts to update.
# @param strategy `refetch` or `upload`.
# @param restart_agent With `upload`, restart the puppet agent service afterwards.
# @param trigger_run With `refetch`, run the agent once in no-op mode right away.
# @return [Hash] target name to task result.
plan openvox_ca::distribute (
  TargetSpec             $ca,
  TargetSpec             $targets,
  Enum[refetch, upload]  $strategy      = 'refetch',
  Boolean                $restart_agent = true,
  Boolean                $trigger_run   = true,
) {
  $ca_targets = get_targets($ca)
  if $ca_targets.length != 1 {
    fail_plan("Expected exactly one CA target, got ${ca_targets.length}", 'openvox_ca/bad-ca-target')
  }

  $source = run_task('openvox_ca::read_ca_bundle', $ca_targets[0]).first.value
  $source['certificates'].each |$c| {
    out::message("CA bundle from ${ca_targets[0].name}: ${c['subject']} expires ${c['not_after'][0, 10]}")
  }

  $results = if $strategy == 'upload' {
    $upload_params = { 'bundle' => $source['bundle'], 'crl' => $source['crl'], 'restart_agent' => $restart_agent }
    run_task('openvox_ca::upload_ca', $targets, $upload_params + { '_catch_errors' => true })
  } else {
    run_task('openvox_ca::remove_localcacert', $targets, 'trigger_run' => $trigger_run, '_catch_errors' => true)
  }

  $results.each |$r| {
    if $r.ok {
      $copies = $r.value['items'].filter |$i| { $i['kind'] == 'local_ca_copy' }
      $expiries = $copies.map |$i| { $i['not_after'][0, 10] }.unique.join(', ')
      out::message(sprintf('%-28s %-8s CA copy now expires %s', $r.target.name, $strategy, $expiries))
    } else {
      out::message(sprintf('%-28s FAILED   %s', $r.target.name, $r.error.message))
    }
  }

  $failed = $results.error_set
  unless $failed.empty {
    fail_plan("Distribution failed on ${failed.names.join(', ')}", 'openvox_ca/distribute-failed', { 'results' => $results })
  }

  return($results.reduce({}) |$acc, $r| { $acc + { $r.target.name => $r.value } })
}
