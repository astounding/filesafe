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

A new file is opened, and SALT + C_F_KEY + C_F_IV are written.  A number
of zero bytes are written to make space to store the HMAC that will be
calculated.

Then the contents of the plaintext file are then encrypted using F_KEY and F_IV
and written to the new file following the file header described above.

A HMAC is calculated on SALT + C_F_KEY + C_F_IV + encrypted file text.
Then the PBKDF2 function is applied to PASS + HMAC using the same SALT
to provide a MAC of sorts.

The HMAC isn't used directly because it would be easier to attempt to
apply a dictionary attack against the passphrase, at least for smaller
encrypted files, without PBKDF2's multiple iterations which increase
computation time for each passphrase guess.  This new HMAC/PBKDF2 hybrid
MAC is written over the top of the zero-bytes previously allocated, and
the file is closed.

Version 1.x of this library and utility stored the HMAC directly instead
utilizing this hybrid MAC scheme.

This new file is the encrypted file.  The old plaintext file is overwritten and
removed.

The HMAC uses the same PASS passphrase and the same hash algorithm that
PBKDF2 uses (SHA-512 by default).

To recover the file, an HMAC is calculated on the encrypted file contents,
excluding the HMAC/PBKDF2 hybrid MAC data.  The PBKDF2 function is applied
supplying PASS + HMAC as the passphrase and the SALT from the file to
calculate the hybrid HMAC/PBKDF2 MAC.  This hybrid MAC is then compared to
the one from the encrypted file.  If the calculated MAC doesn't match the
supplied MAC, then either the file has been corrupted, or the passphrase
is incorrect.

If the MACs match, the encrypted master key material C_F_KEY and C_F_IV
are read from the file.  M_KEY and M_IV are generated using PBKDF2
and PASS with SALT.  F_KEY and F_IV are decrypted using M_KEY and M_IV.
With the file encryption key and initialization vector, the file contents
are then decrypted, revealing the original file plaintext.

The encrypted file can then be safely removed.  The provided utility has
the option of then creating a separate file containing a newly-generated
salt and a PBKDF2 generated sum using the new salt and the original
passphrase.  This provides the user the ability to ask for a passphrase
and compare it (using PBKDF2 and the salt) to the original passphrase
without revealing the original passphrase.

The filesafe utility by default does exactly this, so that if a file
is re-encrypted (which will always use a freshly generated salt and
key), the user is asked for the original passphrase once again.  Should
the user decide to use a new phrase, the temporary file may be safely
deleted.


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

I am debating as to whether I should replace the HMAC in the file header
with a PBKDF2 function, perhaps PBKDF2(passphrase, iterations, HMAC)
so as to make dictionary attacks against passwords much more difficult.
It would result in a slight file format change, so I'd have to bump up
the version, and perhaps provide a fallback to the old method if a
passphrase doesn't seem to match a ciphertext file's stored PBKDF2
result.

