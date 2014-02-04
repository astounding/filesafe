#!/usr/bin/env ruby
# encoding: ASCII-8BIT

require 'test/unit'
require_relative '../lib/filesafe.rb'

class FileSafeDecryptTest < Test::Unit::TestCase
  ## Unicode UTF-8 endash character as ASCII-8BIT binary two-byte, two-character string
  ENDASH = ["2014"].pack('H*')

  ## Encrypted ciphertext:
  CIPHERTEXT = [
    "cda462fe3b2ec9f141fcec6e32198effcb0ed661c35af78878c1e6fb52f5e798" +
    "552e2e02c080cb37aaa298d2a27831d4dabe111101107ee85b21e7b5d91262f1" +
    "f6bf0c63dee422b0a39bbd662202e7cf85feab6c50216b812504119e37f876ce" +
    "baa1a8d402614cfdd5e40a725f0229e19c046f00c8dc264a481b22fece930113" +
    "85debf353626c7dcc34747b5d766ec979d69cf61d4a9bf0db218d4eda7c2b9f9" +
    "e045ac11ebd034caad05fe318aad9cc85500be80b2ff398d62958cb82ee0a583" +
    "b3f0512ef2f9a09dc4dee2e7250ee8db3ce720d84c7f4409e8852ab582118410" +
    "06f9b26163bd0262c7eb7d239c2a66b7228e2372d6bdc9f32dced48e4387829a" +
    "3358abfaf8dff19651e7d06eb8f06dd181df78ced880c1ae4e4aa8e4f2e58d18" +
    "e8603ca8714081e935e1b5d3916de4bf1f3f083ab1b0a70abfd6bf5a25244032" +
    "9327a4da7e1b28e13bddc660ae9e4426ec5bc0e28eba2f794e8ed5c26c9c6717" +
    "e81d194ca2e0e135c3e89a87241d75279eb11352e9ccbbf973de265ebf173916" +
    "421e3c5575350cdd4ff0adb8008aa2ced5ae855940a6d7a221dd651340a4c361" +
    "c1e31e7c6ad4ca6156632cd5f92c48990275b53aca0251d89d61fb25635c965c" +
    "57e615ba69f54cff5ca8b56607e71c3f1a76c81ceb86ab99216da0932b09c72e" +
    "46aae92870105a7c9613acf9d40520692370c1c30249870ba9f0914514389693" +
    "8a3c06414ff868511b52c5fa6d2465c5cad3002724852998ea096ad9eea02b5c" +
    "98faf9954240000938a2ac152b4bcb836fb1fe77ff0f6a3fa0cfebc4d93ac8fc" +
    "9da2c7171319de5a7b034485abb1fbff7ca323be0240394e0cd32d0cfa30c52d" +
    "ea5d02569b95eec39b8bd64559873fdf7eda67523c2fe0234883a0f7e98571ee" +
    "80176609f776be278f7f8665951689b01f6af2ef3002bc1ade88aa398d44039f" +
    "b996d4a094c74925020740573b0c4df4a39cdc689280f535d8e2603fc2c0d4c0" +
    "909933efbd4b99a56564084bab6be5198e0af1d3217ca29def5b422c270c3076" +
    "4af961c2e47d57d520d664e920645a438d339dcaba36246ce4d58fd858e53ceb" +
    "7bbc42cc559eee525f3790810a5e647a7c444308ce47bd61cdfbd416fb935cdf" +
    "f467e9c810c3127c53eb7abe5ca39c3ce98c5b91b3f0696c13c14344717d565d" +
    "e34163cc0af075ef05bda600eeac2c60779b29fdf060e612dc6dd4d81e4c5a38" +
    "5be05409a153177bad7349362c320664043980dd960f923a2de274f01b6b9397" +
    "e24fcd61cd16c10c79649574e7f2874e71dbc563b2b6807359f0799314189000" +
    "6e211a033058adec7a7e58349342803cc784e1e989f1bc552c0a13753ad43661" +
    "71de7f01d35b75e4143a59d738b3b6bd3b45609bdca7996d60564fce0e12df2e" +
    "4658d33b7db5587f431893b44c199d475f7b47a436171d66a6a6d4575c80c6c9" +
    "0f847223367c8c91a74fad3d27cc954ed72640fff84fc33cfb9b4acdef3e2b7c" +
    "810d52e507c74c55cf6123e64b3a6706caa032475793425ebba18c9ca60b3a35" +
    "da91e6d7c4e998fc44aece8a6e0c47184176b4430378e12f1c970a7d27c6350d" +
    "080d79a08b535fe89afb2e02e9d72bb652fb3c09ab948b3fcc43401f0e5719c5" +
    "0cb859975770f0389430eed2c82883e3d07f727b4442f9922712ae763f9c32d4" +
    "84ddd3c2d220ada8e70fef0d5217d24df24f000b827d84ce26702a253717e9bc" +
    "3aaddd3de3ccd833adf668efca3ae6db77290b5de6d6ee5c8223a500066ca69f" +
    "3694ba6b1c15414a7c689f284bad5402d01aa3738196b653c6795e512d839e10" +
    "9f99210803fbc635dd0dcf19c1ea141c8772fb43ea18606f7cae68974b23ff03" +
    "90f0f76cde8e23c19844d95e9564c3174572c45654c2e9e727839b768057993f" +
    "6348c81e45be01e6b8b41cd2156aa05e5587c5fe7c54eb4803ddaa82c717d6d6" +
    "b7874dc209c0e3897ad3760a80af234a2d256e7d4fc120f92a3d9460e933b3ac" +
    "99059edca183cc0e9226d128a799db259f6b0842a7c4d6c80d9b7dce202d33f9" +
    "40fdecc27ffa9201dd2dc18043cae5c4460c0421c272b1b941543a80f7cd2aab" +
    "edf9886c8fdd1ee85aa2ebb158046420fb44a7a0879f5a318a5434de86d58683" +
    "898240d4c9e81b3ae28907472f8bc498ebce1266b6e721f3538d7f4737a8913d" +
    "e29d9f4200dcfa988b3d17fefc4e24d33677f49842955abf06e80cc98ff255e0" +
    "a23db1556b6e9eea66bf121e8152d4ae73f674698cf09d7ee7b7863f9fd00d81" +
    "2f144ef1237ab6a4f2f6c9a69c0129f231df17ff5815a8871ef7fe16fc8efd1a"
  ].pack('H*')

  ## Expected plaintext result as ASCII-8BIT binary string (though
  ## it technically does contain several two-byte UTF-8 Unicode
  ## endash characters mixed in):
  PLAINTEXT = 
    "Four score and seven years ago our fathers brought forth on this "   +
    "continent a new nation, conceived in liberty, and dedicated to the " +
    "proposition that all men are created equal.\n"                       +
    "Now we are engaged in a great civil war, testing whether that "      +
    "nation, or any nation so conceived and so dedicated, can long "      +
    "endure. We are met on a great battlefield of that war. We have "     +
    "come to dedicate a portion of that field, as a final resting place " +
    "for those who here gave their lives that that nation might live. "   +
    "It is altogether fitting and proper that we should do this.\n"       +
    "But, in a larger sense, we can not dedicate, we can not "            +
    "consecrate, we can not hallow this ground. The brave men, living "   +
    "and dead, who struggled here, have consecrated it, far above our "   +
    "poor power to add or detract. The world will little note, nor long " +
    "remember what we say here, but it can never forget what they did "   +
    "here. It is for us the living, rather, to be dedicated here to the " +
    "unfinished work which they who fought here have thus far so nobly "  +
    "advanced. It is rather for us to be here dedicated to the great "    +
    "task remaining before us" + ENDASH + "that from these honored dead " +
    "we take increased devotion to that cause for which they gave the "   +
    "last full measure of devotion" + ENDASH + "that we here highly "     +
    "resolve that these dead shall not have died in vain" + ENDASH        +
    "that this nation, under God, shall have a new birth of freedom"      +
    ENDASH + "and that government of the people, by the people, for the " +
    "people, shall not perish from the earth.\n"

  ## Passphrase used to decrypt:
  PASS      =
    "gfDLT0RbXgW5OvLnoj7mEX (Now doesn't that look fun...)"

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

    assert(PLAINTEXT == plaintext, "Decryption of ciphertext with passphrase failed to match expected plaintext result.")
  end
end

