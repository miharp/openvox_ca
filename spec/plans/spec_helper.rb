# frozen_string_literal: true

# Plan specs run the plans under spec/plans through BoltSpec::Plans with every
# task and command stubbed, so they check the orchestration: guards, the
# order of steps, what is passed to each task, and what happens when a step
# fails. The tasks themselves are covered by the unit specs and the lab.
require 'bolt_spec/plans'
require 'fileutils'
require_relative 'support'

# Bolt finds the module through spec/fixtures/modules, the same place
# rake spec_prep links it. Make the link when running rspec directly.
FIXTURE_MODULES = File.expand_path('../fixtures/modules', __dir__)
MODULE_LINK = File.join(FIXTURE_MODULES, 'openvox_ca')
unless File.exist?(MODULE_LINK)
  FileUtils.mkdir_p(FIXTURE_MODULES)
  File.symlink(File.expand_path('../..', __dir__), MODULE_LINK)
end

module OpenvoxCaBoltContext
  def modulepath
    [FIXTURE_MODULES]
  end
end

RSpec.configure do |config|
  config.include BoltSpec::Plans
  config.include OpenvoxCaBoltContext
  config.include PlanFixtures
  config.before { allow_out_message }
end

BoltSpec::Plans.init
