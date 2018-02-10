const {scrypt,pbkdf2,HMAC_SHA256,WordArray,util}  = require('triplesec')
const {generateSeed, deriveKeypair, deriveAddress} = require('ripple-keypairs')
const params = require('../json/params.json')

//=====================================

const from_utf8 = function(s, i) {
  const b = new Buffer(s, 'utf8')
  const b2 = Buffer.concat([ b, (new Buffer([ i ])) ])
  const ret = WordArray.from_buffer(b2)
  util.scrub_buffer(b)
  util.scrub_buffer(b2)
  return ret
}

export default async function({passphrase, salt, progress_hook}, cb) {
  const scrypt_params = { 
    N             : params.N,
    p             : params.p,
    r             : params.r,
    dkLen         : params.dkLen,
    pbkdf2c       : params.pbkdf2c,
    key           : from_utf8(passphrase, 1),
    salt          : from_utf8(salt, 1),
    progress_hook : progress_hook
  }

  let s1 = await new Promise((res,rej) => scrypt(scrypt_params, res))

  const pbkdf2_params = {
    key           : from_utf8(passphrase, 2),
    salt          : from_utf8(salt, 2),
    c             : params.pbkdf2c,
    dkLen         : params.dkLen,
    progress_hook : progress_hook,
    klass         : HMAC_SHA256
  }

  let s2 = await new Promise((res,rej) => pbkdf2(pbkdf2_params, res))

  s1.xor(s2,{})

  let user_seed_final = s1.to_buffer()

  let garbage = [s1, s2, scrypt_params.key, pbkdf2_params.key]
  garbage.forEach(obj => obj.scrub())

  seed = generateSeed({entropy: user_seed_final})
  out = deriveKeypair(seed)
  out.secret = seed
  out.address = deriveAddress(out.publicKey)
  cb(out)
}