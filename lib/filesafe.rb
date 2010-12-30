#!/usr/bin/env ruby

module FileSafe
  require 'openssl'       ## Encryption/HMAC/Hash algorithms
  require 'securerandom'  ## Cryptographically secure source of random data
  require 'pbkdf2'        ## PBKDF2 algorithm for key material generation
  require 'highline'      ## For reading a passphrase from a terminal
  require 'tempfile'      ## Temporary file creation

  ## CONFIGURATION ITEMS:
  PASSHASH_SUFFIX  = '.pass'
  CIPHER           = 'aes-256-cbc'
  cipher = OpenSSL::Cipher::Cipher.new(CIPHER)
  BLOCK_LEN        = cipher.block_size
  KEY_LEN          = cipher.key_len
  IV_LEN           = cipher.iv_len
  SALT_LEN         = KEY_LEN + IV_LEN
  HMAC_FUNC        = 'sha512'
  HMAC_LEN         = OpenSSL::HMAC.new('', HMAC_FUNC).digest.bytesize
  HEADER_LEN       = KEY_LEN + IV_LEN + SALT_LEN + HMAC_LEN
  ITERATIONS       = 4096
  FILE_CHUNK_LEN   = 65536

  def self.getphrase(check=false)
    begin
      phrase = HighLine.new.ask('Passphrase: '){|q| q.echo = '*' ; q.overwrite = true }
      return phrase unless check
      tmp = HighLine.new.ask('Retype passphrase: '){|q| q.echo = '*' ; q.overwrite = true }
      return phrase if tmp == phrase
    rescue Interrupt
      exit -1
    end while true
  end

  def self.encrypt(file, passphrase=nil)
    raise "Cannot encrypt non-existent file: #{file.inspect}" unless File.exist?(file)
    raise "Cannot encrypt unreadable file: #{file.inspect}" unless File.readable?(file)
    raise "Cannot encrypt unwritable file: #{file.inspect}" unless File.writable?(file)
    passhash   = false
    if File.exist?(file + PASSHASH_SUFFIX)
      raise "Cannot read password hash temporary file: #{(file + PASSHASH_SUFFIX).inspect}" unless File.readable?(file + PASSHASH_SUFFIX)
      raise "Password hash temporary file length is invalid: #{(file + PASSHASH_SUFFIX).inspect}" unless File.size(file + PASSHASH_SUFFIX) == SALT_LEN + HMAC_LEN
      fp = File.open(file + PASSHASH_SUFFIX, File::RDONLY)
      salt = fp.read(SALT_LEN)
      passcheck = fp.read(HMAC_LEN)
      loop do
        passphrase = getphrase if passphrase.nil?
        phash = hashpass(passphrase, salt)
        break if passcheck == phash[1]
        puts "*** ERROR: Passphrase mismatch. Try again, abort, or delete temporary file: #{file + PASSHASH_SUFFIX}"
        passphrase = nil
      end
      passhash = true
    elsif passphrase.nil?
      puts "*** ALERT: Enter your NEW passphrase twice. DO NOT FORGET IT, or you may lose your data!"
      passphrase = getphrase(true)
    end

    ## Use secure random data to populate salt, key, and IV:
    salt      = SecureRandom.random_bytes(SALT_LEN)  ## Acquire some fresh salt
    file_key  = SecureRandom.random_bytes(KEY_LEN)   ## Get some random key material
    file_iv   = SecureRandom.random_bytes(IV_LEN)    ## And a random initialization vector

    ## Encrypt the file key and IV using password-derived keying material:
    keymaterial = PBKDF2.new do |p|
      p.hash_function = HMAC_FUNC
      p.password      = passphrase
      p.salt          = salt
      p.iterations    = ITERATIONS
      p.key_length    = KEY_LEN + IV_LEN
    end.bin_string
    cipher = OpenSSL::Cipher::Cipher.new(CIPHER)
    cipher.encrypt
    ## No padding required for this operation since the file key + IV is
    ## an exact multiple of the cipher block length:
    cipher.padding = 0
    cipher.key     = keymaterial[0,KEY_LEN]
    cipher.iv      = keymaterial[KEY_LEN,IV_LEN]
    encrypted_keymaterial = cipher.update(file_key + file_iv) + cipher.final
    encrypted_file_key = encrypted_keymaterial[0,KEY_LEN]
    encrypted_file_iv  = encrypted_keymaterial[KEY_LEN,IV_LEN]

    ## Open the plaintext file for reading (and later overwriting):
    rfp = File.open(file, File::RDWR|File::EXCL)

    ## Open a temporary ciphertext file for writing:
    wfp = Tempfile.new(File.basename(rfp.path), File.dirname(rfp.path))

    ## Write the salt and encrypted file key + IV and
    ## temporarily fill the HMAC slot with zero-bytes:
    wfp.write(salt + encrypted_file_key + encrypted_file_iv + (0.chr * HMAC_LEN))

    ## Start the HMAC:
    hmac = OpenSSL::HMAC.new(passphrase, HMAC_FUNC)
    hmac << salt
    hmac << encrypted_file_key
    hmac << encrypted_file_iv

    ## Encrypt file with file key + IV:
    cipher = OpenSSL::Cipher::Cipher.new(CIPHER)
    cipher.encrypt
    ## Encryption of file contents uses PCKS#5 padding which OpenSSL should
    ## have enabled by default.  Nevertheless, we explicitly enable it here:
    cipher.padding = 1
    cipher.key     = file_key
    cipher.iv      = file_iv
    until rfp.eof?
      data = rfp.read(FILE_CHUNK_LEN)
      if data.bytesize > 0
        data = cipher.update(data)
        hmac << data
        wfp.write(data)
      end
    end
    data = cipher.final
    if data.bytesize > 0
      ## Save the last bit-o-data and update the HMAC:
      wfp.write(data)
      hmac << data
    end

    ## Write HMAC digest to file:
    wfp.pos = SALT_LEN + KEY_LEN + IV_LEN
    wfp.write(hmac.digest)

    ## Overwrite the original plaintext file with zero bytes.
    ## This adds a small measure of security against recovering
    ## the original unencrypted contents.  It would likely be
    ## better to overwrite the file multiple times with different
    ## bit patterns, including one or more iterations using
    ## high-quality random data.
    rfp.seek(0,File::SEEK_END)
    fsize = rfp.pos
    rfp.pos = 0
    while rfp.pos + FILE_CHUNK_LEN < fsize
      rfp.write(0.chr * FILE_CHUNK_LEN)
    end
    rfp.write(0.chr * (fsize - rfp.pos)) if rfp.pos < fsize
    rfp.close

    ## Copy file ownership/permissions:
    stat = File.stat(rfp.path)
    wfp.chown(stat.uid, stat.gid)
    wfp.chmod(stat.mode)

    ## Close the ciphertext temporary file without deleting:
    wfp.close(false)

    ## Rename temporary file to permanent name:
    File.rename(wfp.path, rfp.path)

    ## Remove password hash temp. file:
    File.delete(file + PASSHASH_SUFFIX) if passhash
  end

  def self.decrypt(file, passphrase=nil, notemp=true)
    raise "Cannot decrypt non-existent file: #{file.inspect}" unless File.exist?(file)
    raise "Cannot decrypt unreadable file: #{file.inspect}" unless File.readable?(file)
    raise "Cannot decrypt unwritable file: #{file.inspect}" unless File.writable?(file)
    fsize = File.size(file)
    raise "File is not in valid encrypted format: #{file.inspect}" unless fsize > HEADER_LEN && (fsize - HEADER_LEN) % BLOCK_LEN == 0
    salt = encrypted_file_key = encrypted_file_iv = nil
    loop do
      passphrase = getphrase if passphrase.nil?
      fp = File.open(file, File::RDONLY)
      salt               = fp.read(SALT_LEN)
      encrypted_file_key = fp.read(KEY_LEN)
      encrypted_file_iv  = fp.read(IV_LEN)
      file_hmac          = fp.read(HMAC_LEN)
      test_hmac = OpenSSL::HMAC.new(passphrase, HMAC_FUNC)
      test_hmac << salt
      test_hmac << encrypted_file_key
      test_hmac << encrypted_file_iv
      until fp.eof?
        data = fp.read(FILE_CHUNK_LEN)
        test_hmac << data unless data.bytesize == 0
      end
      fp.close
      break if test_hmac.digest == file_hmac
      puts "*** ERROR: Incorrect passphrase, or file is not encrypted. Try again or abort."
      passphrase = nil
    end

    ## Extract and decrypt the encrypted file key + IV.
    ## First, regenerate the password-based key material that encrypts the
    ## file key + IV:
    keymaterial = PBKDF2.new do |p|
      p.hash_function = HMAC_FUNC
      p.password      = passphrase
      p.salt          = salt
      p.iterations    = ITERATIONS
      p.key_length    = KEY_LEN + IV_LEN
    end.bin_string
    cipher = OpenSSL::Cipher::Cipher.new(CIPHER)
    cipher.decrypt
    cipher.padding = 0 ## No padding is required for this operation
    cipher.key     = keymaterial[0,KEY_LEN]
    cipher.iv      = keymaterial[KEY_LEN,IV_LEN]
    ## Decrypt file key + IV:
    keymaterial = cipher.update(encrypted_file_key + encrypted_file_iv) + cipher.final
    file_key = keymaterial[0,KEY_LEN]
    file_iv  = keymaterial[KEY_LEN,IV_LEN]

    ## Decrypt file:
    cipher = OpenSSL::Cipher::Cipher.new(CIPHER)
    cipher.decrypt
    cipher.padding = 1 ## File contents use PCKS#5 padding,OpenSSL's default method
    cipher.key     = file_key
    cipher.iv      = file_iv

    ## Open ciphertext file for reading:
    rfp = File.open(file, File::RDONLY|File::EXCL)

    ## Open a temporary plaintext file for writing:
    wfp = Tempfile.new(File.basename(rfp.path), File.dirname(rfp.path))

    ## Begin reading the ciphertext beyond the headers:
    rfp.pos = HEADER_LEN  ## Skip headers
    until rfp.eof?
      data = rfp.read(FILE_CHUNK_LEN)
      if data.bytesize > 0
        data = cipher.update(data)
        wfp.write(data)
      end
    end
    data = cipher.final
    wfp.write(data) if data.bytesize > 0

    ## Close the ciphertext source file:
    rfp.close

    ## Copy file ownership/permissions:
    stat = File.stat(rfp.path)
    wfp.chown(stat.uid, stat.gid)
    wfp.chmod(stat.mode)

    ## Close the plaintext temporary file without deleting:
    wfp.close(false)

    ## Rename temporary file to permanent name:
    File.rename(wfp.path, rfp.path)

    unless notemp
      ## Write password hash temp. file using PBKDF2 as an iterated hash of sorts of HMAC_LEN bytes:
      File.open(file + PASSHASH_SUFFIX, File::WRONLY|File::EXCL|File::CREAT) {|f| f.write(hashpass(passphrase).join)}
    end
  end
  
  ## Use PBKDF2 as if it were a hash function with salt to generate a
  ## next-to-impossible-to-reverse-or-deliberately-collide hash of the
  ## supplied passphrase:
  def self.hashpass(passphrase, salt=nil)
    ## Grab a new chunk of secure random data if no salt was supplied:
    salt = SecureRandom.random_bytes(SALT_LEN) if salt.nil?
    hash = PBKDF2.new do |p|
      p.hash_function = HMAC_FUNC
      p.password      = passphrase
      p.salt          = salt
      p.iterations    = ITERATIONS
      p.key_length    = HMAC_LEN
    end.bin_string
    [ salt, hash ]
  end

end
