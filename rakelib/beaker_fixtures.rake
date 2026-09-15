# frozen_string_literal: true

# Install fixtures before acceptance tests and clean them up after a green run.
# Kept out of the Rakefile because that file is managed by modulesync.
if Rake::Task.task_defined?(:beaker) && Rake::Task.task_defined?('fixtures:prep')
  task beaker: 'fixtures:prep'
  Rake::Task[:beaker].enhance do
    Rake::Task['fixtures:clean'].invoke
  end
end
