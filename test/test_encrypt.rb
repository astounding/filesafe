#!/usr/bin/env ruby
# encoding: ASCII-8BIT

require 'test/unit'
require_relative '../lib/filesafe.rb'

class FileSafeEncryptTest < Test::Unit::TestCase
  PLAINTEXT = [
    "eb82c419f0bec066419fd1dd2d18fbe540ee9419f0e16dbb643effc0cb108f98" +
    "be67cd67bce8745c6ad6259421093606186023b6ff86a684b086321822247489" +
    "a264f20ea51c87ec72105f230a5f79520fe090b17c70e6e1df2ab0a0f28140eb" +
    "7481399d4a327ceb5d7763d9f4df4810a8da896fc5e0ca068402359dc24272fe" +
    "4fa12cd9d40a9f9b39e59c4d598f1db2f18e6932d34908a3a8591c818b146f64" +
    "c37bc4d67610678dfa801502ca84d21e3eab03d9cfd862dc04e7f31aaee78d5d" +
    "24b7ab09971f489ac9e16215f30e2b586e861ac39ffa34d656f084c29d5df1e9" +
    "c22612b1fa1bfb955c745af3d64036e38c526ab20a37400122dac284f4ddbbd1" +
    "ec706229c49422e6ab3ccc8a1766ab13cb876c2cca998aa46afa5e0433b21d2b" +
    "9b5d4b3770aac592d19c5ff21202dc5d27e12b794ad5df26f97ab2c19a16f5ee" +
    "2c21c90f8e462e43917cd109118d2cbc888dc6d29727cdba22857549b1900754" +
    "b22e71d27df5a57b85da7e13ed6acb4768969491473d13c9298f980b08ba032e"
  ].pack('H*')

  DEBUG_PARAMS = [
    ## SALT (48 bytes, 384 bits):
    "4e7953c3f5434aabbb358af82363592ddbf42f707f6cfaf9" + 
    "d61710b0cc7275829f6195881712baf29362cd7f73523de3" +
    ## KEY (32 bytes, 256 bits):
    "16cdd98ca1eacffd7685ab387ad882b603c93c4a26e5bf874747b15e122acd76" +
    ## IV (16 bytes, 128 bits):
    "1a2466b2480b84d571b1749e9bab67f5"
  ].pack('H*')

  CIPHERTEXT = [
    ## SALT (48 bytes, 384 bits):
    "4e7953c3f5434aabbb358af82363592ddbf42f707f6cfaf9" +
    "d61710b0cc7275829f6195881712baf29362cd7f73523de3" +
    ## C_F_KEY (32 bytes, 256 bits):
    "d83eab0e69e061212206f8a8a24e83150370eebbb4458464f8c3d929b922c35e" +
    ## C_F_IV (16 bytes, 128 bits):
    "51a8cf9549d3dcb1d83d504d31d160a1" +
    ## PBKDF2(passphrase + HMAC(SALT + C_F_KEY + C_F_IV)) (512 bits, 64 bytes):
    "b1e619b7cdae804fb127440458852f2955fb3d0a5a2121c93ea03427f7f1d029" +
    "ae88b0b3acc2b05d2dcc0af79934282e469024e8a9cd8f9f5671afaa6290784f" +
    ## CIPHERTEXT BLOCKS:
    "7852374484758b04bcf661a667dc2e03576f231897a52426f9cd547667b6ef16" +
    "bcf17d2f23e9a30115a1619a219158259e64d13d3197019af92a8ccb22d24e0e" +
    "248d48f867223086eb5ec729878fbe1696d83f357791c2af221ba7843cbb149c" +
    "9ca1e50816dd14ccff97cf37e554d87b8ee3a4d121025877554858e3d365ab6a" +
    "0440e65bf191d51f58eb3cee355101ab507dedb1700cb668843f698a4e8539d2" +
    "324416336d479b156232d9759719596fe8d8ef494a33e7859d349a8764866b43" +
    "0395d4f88234fcec7d9972ded3ec7418bcf098f0004245d3733ed80c7a2e6a5f" +
    "ada107b1b7cc770bf9063e5f86de817c3fb72c2b8c3354c85c1c32770fb81052" +
    "f2aab51e76233b755ba7712fb1389c267d994ded420c30fed22834cf5d0b1924" +
    "9c5a297e5f57e5b9a7f2318b6edccf9a1d2b024cc6c4e7d8bbf3435185c8f7e0" +
    "caa97abc688873da904deadc744c216ef044901edce3d239ffffc4b4f999a3cc" +
    "32671bd83819b0478638eef85b5063bd5ba2cf9bc1f57ad05afc44fe35ff546f" +
    "563b163ddb641c2e8f9bcd603b7d5c12"
  ].pack('H*')
  PASS      =
    "This is my very TOP SECRET passphrase.  Please don't share it!"

  def setup
    ## Create a temporary file:
    @testfile = 'test.out'
    File.open(@testfile,'w'){|f| f.print PLAINTEXT}
  end

  def teardown
    File.unlink(@testfile)
  end

  def test_encrypt
    ## Encrypt data:
    FileSafe.encrypt(@testfile, PASS, true, DEBUG_PARAMS)

    ## Read encrypted file contents:
    ciphertext = File.read(@testfile, :encoding => Encoding::BINARY)

    assert(CIPHERTEXT == ciphertext, "Resulting encryption of plaintext to ciphertext does NOT match expected ciphertext.")
  end
end

