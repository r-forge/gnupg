require(svUnit)

# test functions are called in lexicographic order.
# $Id$

test.000.canCreateMainObject <- function() {
  gpg <- GnuPG$new(homedir=".")
  assertEquals("gnupg", class(gpg))
}

