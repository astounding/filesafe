#!/usr/bin/env ruby
# encoding: ASCII-8BIT

require 'test/unit'
require_relative '../lib/filesafe.rb'

class FileSafeDecryptTest < Test::Unit::TestCase
  CIPHERTEXT = [
    "60e8aacea874e36f39fef5f51cf727252359c575230b7306b6379194" +
    "12bc53e9106ddaecc0ded13503e6ef9d3ff9f0285bb133d3d88464c0" +
    "eea4f728ae509942a4e8be070a70d49b8668ddbda2102412ca42c917" +
    "bd74c824ae6b35bb697a0fccd8f0822e310f96bfc34546e289e6dbed" +
    "f3dd30eca6585ad344593ca65f6aa323722a29c1c19257b135756340" +
    "7a88de6a92a85dae5dd9ea0cb8a2ccaf3c45bace571cb0c791186837" +
    "a3a6ff650545286afbd75087b42582da571521fbc74fa3499dc22ebc" +
    "8482e13c4055313b38a0cf79"].pack('H*')
  PLAINTEXT = 
    "This is a PLAINTEXT file for testing\n"
  PASS      =
    "topsecretstuff"

  def setup
    ## Create a temporary file:
    @testfile = 'test.out'
    File.open(@testfile,'w'){|f| f.print CIPHERTEXT }
  end

  def teardown
    File.unlink(@testfile)
  end

  def test_decrypt
    ## Decrypt data:
    FileSafe.decrypt(@testfile, PASS, true)

    ## Read decrypted file contents:
    plaintext = File.open(@testfile,'r'){|f| f.read}

    assert(PLAINTEXT == plaintext)
  end
end

