require(svUnit)

# test functions are called in lexicographic order.
# $Id$

test.000.canCreateMainObject <- function() {
  gpg <- GnuPG$new(homedir=".")
  checkEquals("gnupg", as.character(class(gpg)))
}

test.010.mainObjectHasPublicKey <- function() {
  gpg <- GnuPG$new(homedir=".")
  fail("not implemented yet")
}

test.100.encrypt.decrypt <- function() {
  gpg <- GnuPG$new(homedir=".")
  checkEquals("some text", gpg$decrypt(gpg$encrypt("some text", armor=TRUE)))
}

test.200.sign.verify <- function() {
  gpg <- GnuPG$new(homedir=".")
  checkTrue(gpg$verify(gpg$clearsign("some text", armor=TRUE, passphrase="")))
}
