#!/usr/bin/env ruby

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
    goal = "6c726ee33ad9e171612d646403b3e01bba0451574cde9b0af90d957e" +
           "1b33c0830db1ac63b986f755faa8b1e9a944dbf4c7086da2eae122c3" +
           "9f42a359ef12536c"
    salt = [salt].pack('H*')
    goal = [goal].pack('H*')
    hash = FileSafe.pbkdf2(pass, salt, FileSafe::HMAC_LEN)
    assert(hash == goal)
  end
end

