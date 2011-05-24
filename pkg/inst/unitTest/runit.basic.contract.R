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

test.210.sign <- function() {
  private <- SshKey$new("/home/mario/.ssh/id_rsa")
  encoded_data <- 'InNvbWUgbG9nZ2luZyBtZXNzYWdlLCBhbHJlYWR5IGZvcm1hdHRlZCI='
  private$sign(encoded_data)
  "\x00\x00\x00\x07ssh-rsa\x00\x00\x01\x00UZ\x95]\xf6\xa0\n\x12\xbcC\x07\xb6\x13?6^\x08]c\x1et\xbcN#?\x9b\xacR\xc2Z\xfa\xefp\x07\xbes\xc7Sm\xf0\xe3.\xd2\xce\xa3\xfek\x92\xfb\xe6\x81\xfa\xb1\xf7\x1c\x87\xb5A\xe4Ee\xa0\xe6\x8e<\x05f\x01Bg[\x05r\x973\xf8[^a\x90\xffd<\x89F\xbahR1\x7fI\xbb\xa0\xd1\x1a'\x96\x07'|\xffY\xcc4\x14\x8b\x16\xb7\x0b\x85\x19\x12\xd2\x94\xf9\x95\xcc\x157\x1f7L\xd7F\x06UGp\xbc\x19\x18\xb0\xc6\x01\xb3\xe8\xfd\x15\xa3\xd1g\xa3\x9c\xe5\x85R\x18\xe1\xf88\xc1\xdfd_I@\xfa\xade\x96:\xbd\x18;\xdbq\xa6T\xa8\xb9\xaaq\xaa\xc3\x0f\xd5\x85\x8c\xfa\n{5P&\x89\xe2\xd4\xd9\xa4\xe3.|\x01\x88G`\xec!\xef\xbd\xac\xf5\xc7\x87\xcb}\x8aJk\xc0\xe2'\xf4\x81\xf4\xfa+\x03\x98&\xaa\x89Kc\xa3\xca\xde\xdb\x04\x16\xb2\xe6yj\x8b\x8c\xa6]<\x1c\x82\x08\\\x8csV\x00{\xc5bC\x93W'\xd3f"
}
