DESCRIPTION

FileSafe

Written by Aaron D. Gifford - http://www.aarongifford.com/

A simple Ruby script for encrypting/decrypting files using 256-bit AES
and a master key derived from a password/passphrase via the PBKDF2
function.


I wrote this script for use on several systems where I needed to
regularly encrypt/decrypt one or more files using a password or
passphrase.  The method used should be reasonably secure for the uses I
required.  I have NOT adapted the script (yet) for non-POSIX
environments (Windows) however.

This script was written and tested using Ruby 1.9.x.  No attempts to
adapt or test it under earlier Ruby versions have been made.

ENCRYPTED FILE FORMAT

Before a file is encrypted, some cryptographically secure random data
is obtained:

  SALT  = securely generated random salt data
  F_KEY = securely generated random key data
  F_IV  = securely generated random initialization vector data

The F_KEY and F_IV will be used to encrypt the plaintext file.  In
order to keep them secure, they will be encrypted using a master key
and initialization vector derived from the passphrase supplied by
the user and the SALT.

  PASS  = passphrase supplied by the user of the utility
  M_KEY = master key derived as described below
  M_IV  = master initilization vector derived as described below

In order to derive M_KEY and M_IV, the PBKDF2 algorithm as described
in RFC2898 is used, passing PASS and SALT to it, using the configured
hash (SHA-512 by default) and number of iterations (4096 by default).

Once M_KEY and M_IV are obtained, 256-bit AES in CBC mode is used to
encrypt F_KEY + F_IV to obtain:

  C_F_KEY = ciphertext encrypted version of F_KEY, encrypted using M_KEY and  M_IV
  C_F_IV  = ciphertext encrypted version of F_IV, encrypted using M_KEY and M_IV

A new file is opened, and SALT + C_F_KEY + C_F_IV are written.  The
contents of the plaintext file are then encrypted using F_KEY and F_IV
and written to the new file following the salt and encrypted key and vector.

Finally, a HMAC of SALT + C_F_KEY + C_F_IV + encrypted file text is written
to the end of the new file and it is closed.

This new file is the encrypted file.  The old plaintext file is overwritten and
removed.

The HMAC uses the same PASS passphrase and the same hash algorithm that
PBKDF2 uses (SHA-512 by default).

To recover the file, an HMAC is calculated on the encrypted file contents
excluding the trailing saved HMAC data appended to the end.  This calculated
HMAC is compared to the saved HMAC.  If they don't match, then either the
file has been corrupted, or the passphrase is incorrect or different.

If the HMACs match, the SALT is read from the start of the file as well
as the encrypted master key material C_F_KEY and C_F_IV.  Using PBKDF2
and the SALT and PASS, the master key material is recovered, M_KEY and M_IV,
which then are used to decrypt the file keys F_KEY and F_IV.  These file
keys are used to decrypt and recover the plaintext.


LICENSE

This script is licensed under an MIT-style license.  See the LICENSE.txt file.


REQUIREMENTS

This script requires or relies on:
  openssl       -- encryption/HMAC/hash algorithms
  securerandom  -- cryptographically secure random data
  tempfile      -- for temporary file creation

It uses the following gems:
  pbkdf2        -- for the password-based key derivitive function PBKDF2
  highline      -- for reading a password/passphrase from a terminal


WEB SITE

The latest version can be found at the author's web site:

* http://www.aarongifford.com/computers/filesafe/index.html


SUGGESTIONS / BUGS

Please report bugs by going to the author's web site and clicking on the
"Contact Me" link in the left-hand menu.  The direct URL is:

* http://www.aarongifford.com/leaveanote.html



Thank you!
-- Aaron D. Gifford

