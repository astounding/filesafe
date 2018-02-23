require 'rubygems/package_task'
require 'rdoc/task'
require 'rake/testtask'

gemspec = Gem::Specification.new do |spec|
  spec.name         = 'filesafe'
  spec.version      = File.open('VERSION.txt','r').to_a.join.strip
  spec.licenses     = ['MIT']
  spec.date         = File.mtime('VERSION.txt')
  spec.author       = 'Aaron D. Gifford'
  spec.homepage     = 'http://www.aarongifford.com/computers/filesafe/'
  spec.summary      = 'Encrypt/decrypt files with a random 256-bit AES key secured by a passphrase derived master key using PBKDF2'
  spec.description  = 'A utility script for encrypting and decrypting files using a randomly generated 256-bit AES key and initialization vector secured using the PBKDF2 password/passphrase key derivation algorithm to secure the file key and IV.'
  spec.has_rdoc     = true ## Very limited documentation
  spec.extra_rdoc_files = [ 'README.txt' ]
  spec.require_paths = [ 'lib' ]
  spec.files = FileList[
    'README.txt',
    'VERSION.txt',
    'Rakefile',
    'bin/*',
    'lib/*',
    'test/*'
  ]
  spec.executables = [ 'filesafe' ]
  spec.add_runtime_dependency 'highline', '~>1.6.1', '>= 1.6.1'
end

Gem::PackageTask.new(gemspec) do |pkg|
  pkg.need_zip = true
  pkg.need_tar = true
end

RDoc::Task.new do |rdoc|
  rdoc.name     = 'rdoc'
  rdoc.main     = 'README.txt'
  rdoc.rdoc_dir = 'doc'
  rdoc.rdoc_files.include('README.txt', 'lib/*')
end

Rake::TestTask.new do |t|
  t.test_files = FileList['test/test*.rb']
  t.verbose = true
end

task :default => [
  'pkg/filesafe-' + File.open('VERSION.txt','r').to_a.join.strip + '.gem',
  :rdoc
]

