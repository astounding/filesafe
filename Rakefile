require 'rubygems/commands/push_command'
require 'rake/gempackagetask'
require 'rake/rdoctask'
require 'rake/testtask'

gemspec = Gem::Specification.new do |spec|
  spec.name         = 'filesafe'
  spec.version      = File.open('VERSION.txt','r').to_a.join.strip
  spec.date         = File.mtime('VERSION.txt')
  spec.author       = 'Aaron D. Gifford'
  spec.homepage     = 'http://www.aarongifford.com/computers/filesafe/'
  spec.summary      = 'Encrypt/decrypt files with a random 256-bit AES key secured by a passphrase derived master key using PBKDF2'
  spec.description  = 'A utility script for encrypting and decrypting files using a randomly generated 256-bit AES key and initialization vector secured using the PBKDF2 password/passphrase key derivation algorithm to secure the file key and IV.'
  spec.has_rdoc     = false ## No documentation yet
  spec.extra_rdoc_files = [ 'README.txt' ]
  spec.files = FileList[
    'README.txt',
    'VERSION.txt',
    'Rakefile',
    'bin/*',
    'lib/*',
    'test/*'
  ]
  spec.executables = [ 'filesafe' ]
  spec.add_dependency('pbkdf2', '>= 0.1.0')
  spec.add_dependency('highline', '>= 1.6.1')
end

Rake::GemPackageTask.new(gemspec) do |pkg|
  pkg.need_zip = true
  pkg.need_tar = true
end

Rake::RDocTask.new do |rdoc|
  rdoc.name     = 'rdoc'
  rdoc.main     = 'README.txt'
  rdoc.rdoc_dir = 'doc'
  rdoc.rdoc_files.include('README.txt')
end

Rake::TestTask.new do |t|
  t.test_files = FileList['test/test*.rb']
  t.verbose = true
end

task :default => [
  'pkg/filesafe-' + File.open('VERSION.txt','r').to_a.join.strip + '.gem',
  :rdoc
]

task :publish => [ :default ] do
  push = Gem::Commands::PushCommand.new
  push.arguments << 'pkg/filesafe-' + File.open('VERSION.txt','r'){|f| f.read}.strip + '.gem'
  push.execute
end

