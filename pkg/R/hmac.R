library(digest)

pad.with.zeros <- function(k) {
  as.raw(c(charToRaw(k), rep(0, 64 - nchar(k))))
}

# splits a hex-string into the values it contains.
as.raw.digest <- function(dd) {
  parts <- sapply(seq(1, nchar(dd), 2),
                  function(i) { substr(dd, i, i + 1) })
  as.raw(as.hexmode(parts))
}

hmac <- function(k, msg, algo) {
  padded.key <- pad.with.zeros(k)
  i.xored.key <- xor(pad.with.zeros(k), as.raw(0x36))
  character.digest <- digest(c(i.xored.key, charToRaw(msg)), algo=algo, serialize=FALSE)
  raw.digest <- as.raw.digest(character.digest)
  o.xored.key <- xor(padded.key, as.raw(0x5c))
  result <- digest(c(o.xored.key, raw.digest), algo=algo, serialize=FALSE)
  return(result)
}
