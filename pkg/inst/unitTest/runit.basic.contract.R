require(svUnit)

# test functions are called in lexicographic order.
# $Id$

test.000.canCreateMainObject <- function() {
  gpg <- SshKey$new("/home/mario/.ssh/id_rsa")
  checkEquals("sshkey", as.character(class(gpg)))
}

test.010.mainObjectIsPrivateKey <- function() {
  gpg <- SshKey$new("/home/mario/.ssh/id_rsa")
  checkEquals("sshkey", as.character(class(gpg)))
  checkTrue(gpg$isPrivate())
  checkFalse(gpg$isPublic())
}

test.011.mainObjectIsPublicKey <- function() {
  gpg <- SshKey$new("/home/mario/.ssh/id_rsa.pub")
  checkEquals("sshkey", as.character(class(gpg)))
  checkFalse(gpg$isPrivate())
  checkTrue(gpg$isPublic())
}

test.200.sign.verify <- function() {
  public <- SshKey$new("/home/mario/.ssh/id_rsa.pub")
  private <- SshKey$new("/home/mario/.ssh/id_rsa")
  msg <- "some logging message, already formatted"
  checkTrue(public$verify(private$sign(msg), msg))
}
