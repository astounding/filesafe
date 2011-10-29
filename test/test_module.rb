#!/usr/bin/env ruby
# encoding: ASCII-8BIT

require 'test/unit'
require 'digest/sha2'
require_relative '../lib/filesafe.rb'

class FileSafeModuleTest < Test::Unit::TestCase
  FILESAFE = File.join(File.dirname(__FILE__), '..', 'bin', 'filesafe')
  def setup
    ## Create a temporary file:
    @testfile = 'test.out'
    @passphrase = 'four score and seven years ago'
    File.open(@testfile,'w'){|f| f.puts "Some more test data"}

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

  def test_module
    ## Encrypt file:
    FileSafe.encrypt(@testfile, @passphrase)
   
    assert(file_hash(@testfile) != @plaintext_hash)
    assert(File.size(@testfile) != @plaintext_size)

    ## Decrypt file:
    FileSafe.decrypt(@testfile, @passphrase, true)

    assert(file_hash(@testfile) == @plaintext_hash)
    assert(File.size(@testfile) == @plaintext_size)
  end

  def test_pbkdf2
    pass = "When in the course of human events..."
    salt = "01caf8e2e844a37810280f231f3059aca54e631528c1c57eb643df2c" +
           "8c6c74bc4a6136784ecff873dcd09a80059f6e80"
    goal = "74a1aa134ea370cbff2776f9271e500e7774a567c47c565cf4c489f1" +
           "c029d0fb406d195f7678001d454ef803e6b55394fd52257261a5bb81" +
           "413db6b65af819a5"

    salt = [salt].pack('H*')
    goal = [goal].pack('H*')
    assert(FileSafe::HMAC_LEN == goal.bytesize, "Module HMAC length has changed since test was created. (Expected #{goal.bytesize} bytes, length is now #{FileSafe::HMAC_LEN} bytes.)")
    assert(FileSafe::ITERATIONS == 16384, "Module ITERATIONS has changed. (Expected 16384 iterations, currently set to #{FileSafe::ITERATIONS} iterations.)")
    assert(FileSafe::HMAC_FUNC == 'sha512', "Module HMAC_FUNC has changed. (Expected 'sha512' hash function for HMAC, instead of '#{FileSafe::HMAC_FUNC}' instead.)")
    hash = FileSafe.pbkdf2(pass, salt, FileSafe::HMAC_LEN)
    assert(hash == goal, "PBKDF2 output does NOT match expected value.")
  end
end

