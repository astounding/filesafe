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


LICENSE

This script is licensed under an MIT-style license.  See the license header at the top of the script source code.


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

