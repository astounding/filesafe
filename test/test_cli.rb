#!/usr/bin/env ruby

require 'test/unit'
require 'digest/sha2'

class FileSafeCLITest < Test::Unit::TestCase
  FILESAFE = File.join(File.dirname(__FILE__), '..', 'bin', 'filesafe')
  def setup
    ## Create a temporary file:
    @testfile = 'test.out'
    @passphrase = 'this is the encryption passphrase'
    File.open(@testfile,'w'){|f| f.puts "Test data"}

    ## Save SHA256 digest of the file:
    @plaintext_hash = file_hash(@testfile)
    @plaintext_size = File.size(@testfile)
  end

  def file_hash(filename)
    Digest::SHA256.hexdigest(File.open(filename, 'r'){|f| f.read})
  end

  def teardown
    File.unlink(@testfile)
  end

  def test_cli
    ## Encrypt file:
    `#{FILESAFE} -e -p '#{@passphrase}' '#{@testfile}'`
   
    assert(file_hash(@testfile) != @plaintext_hash)
    assert(File.size(@testfile) != @plaintext_size)

    ## Decrypt file:
    `#{FILESAFE} -d -n -p '#{@passphrase}' '#{@testfile}'`

    assert(file_hash(@testfile) == @plaintext_hash)
    assert(File.size(@testfile) == @plaintext_size)
  end
end

