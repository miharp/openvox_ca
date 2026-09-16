# @summary Report certificate expiry across an OpenVox deployment. Read-only.
#
# Runs the CA check on the CA host and the host certificate check on every
# other target, prints one line per certificate sorted by days left, and
# returns the raw reports so another plan or a scheduled run can consume them.
#
# The CA check also audits every certificate the CA has issued, from the
# CA's signed directory, so the fleet's certificate expiry is visible from
# the CA host alone without an inventory of agents. By default only the
# issued certificates that are due or expired are listed; counts for the
# whole directory are always printed. An expiring issued certificate does
# not affect the CA's own status.
#
# @param ca The CA host. Exactly one target.
# @param targets Other hosts to check. Optional.
# @param warn_days Flag anything that expires within this many days.
# @param issued Which issued certificates to list: those due within warn_days or expired, all, or none.
# @return [Hash] `ca` holds the CA host's report, `hosts` maps target name to report.
plan openvox_ca::check (
  TargetSpec             $ca,
  Optional[TargetSpec]   $targets   = undef,
  Integer[0]             $warn_days = 90,
  Enum[due, all, none]   $issued    = 'due',
) {
  $ca_targets = get_targets($ca)
  if $ca_targets.length != 1 {
    fail_plan("Expected exactly one CA target, got ${ca_targets.length}", 'openvox_ca/bad-ca-target')
  }
  $ca_name = $ca_targets[0].name

  $ca_report = run_task('openvox_ca::check_ca', $ca_targets[0], 'warn_days' => $warn_days, 'issued' => $issued).first.value

  $host_reports = if $targets =~ NotUndef {
    $results = run_task('openvox_ca::check_host_cert', $targets, 'warn_days' => $warn_days, '_catch_errors' => true)
    $results.reduce({}) |$acc, $result| { $acc + { $result.target.name => $result.value } }
  } else {
    {}
  }

  $ca_rows = $ca_report['items'].map |$item| { $item + { 'host' => $ca_name } }
  $host_rows = $host_reports.map |$name, $report| {
    $items = $report['items'].lest || { [] }
    $items.map |$item| { $item + { 'host' => $name } }
  }.flatten
  $rows = ($ca_rows + $host_rows).sort |$a, $b| { compare($a['days_left'], $b['days_left']) }

  out::message(sprintf('%-8s %-28s %-14s %-10s %6s  %s', 'STATUS', 'HOST', 'KIND', 'EXPIRES', 'DAYS', 'SUBJECT'))
  $rows.each |$row| {
    if $row['kind'] == 'crl' {
      $expires = $row['next_update']
      $subject = $row['issuer']
    } elsif $row['kind'] == 'issued_cert' and $row['revoked'] {
      $expires = $row['not_after']
      $subject = "${row['subject']} (revoked)"
    } else {
      $expires = $row['not_after']
      $subject = $row['subject']
    }
    out::message(sprintf('%-8s %-28s %-14s %-10s %6d  %s', $row['status'], $row['host'], $row['kind'], $expires[0, 10], $row['days_left'], $subject))
  }

  if $ca_report['issued'] =~ NotUndef {
    $s = $ca_report['issued']
    out::message("Issued certificates on ${ca_name}: ${s['total']} total, ${s['warn']} due within ${warn_days} days, ${s['expired']} expired, ${s['revoked']} revoked")
  }

  $failed = $host_reports.filter |$name, $report| { $report['_error'] =~ NotUndef }
  unless $failed.empty {
    out::message("Could not check: ${failed.keys.join(', ')}")
  }

  return({ 'ca' => $ca_report, 'hosts' => $host_reports })
}
