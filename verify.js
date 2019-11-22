/**
 * The whole process of generating random numbers in GINAR utilizing a so-called
 * verifiable random functions. Based on an input (i.e the ticketID) from the client,
 * each GINARATOR caculates the VRF using his private key and produces the outcomes.
 * This outcome then becomes the contribution of this GINARATOR to generating the final random number.
 * We utilize the VRF based on description of Praos which can be found at this link:
 * https://eprint.iacr.org/2017/573.pdf
 *  
 * This script serves the purpose of verifying the correctness of the VRF cacluation. 
 */

const keccak256 = require('js-sha3').keccak256;
const BN = require('bn.js');
var EC = require('elliptic').ec
var ec = new EC('secp256k1')



/**YOUR INPUT AREA */
let ticket = "INPUT THE TICKET HERE"
let publicKey = "INPUT THE PUBLIC KEY HERE (IN HEXADECIMAL FORM)"
let credential = "INPUT THE CREDENTIAL HERE"

/**Sample input
 * let ticket = "0000101100001011000010110000101100001011000010110000101100001011000001"
 * let publicKey = "0300655927aa9dfa5a4d303debdd3acc62e11193c6a09410993f8d9ad35a95c6f7"
 * let credential = "036b5b6d70cb2b6108db6a1b157c9206970022508d28364f9777041875d88d9ff725f11709c78c6bdb092aaccf40853ad6400205ea19ede865222c14e34526f39e9ac3715ba00c1741541c7d6659651b5c9f68fb7fb1e8ad69f72a77d08d2032f2"
 */

/**Retrieve the generator of the elliptic curve
 */
function getCurveGenerator() {
  return ec.curve.g
}

/**Retrieve the order (the number of points) of the elliptic curve
 */
function getCurveOrder() {
  return ec.curve.n.clone()
}


/**Map an arbitrary message to a point on the elliptic curve.
 * The implementation is based on [BLS]'s MapToGroup specification.
 * Note that the curve here has cofactor of 1, so the subgroup contains the whole curve
 * 
 * @param  {string} m the message to be map
 */
function MapOntoCurve(m) {
  for (let i = 1; i < 5000; i++) {
    let temp = i.toString(16) + m

    if (temp.length % 2 == 1) {
      temp = '0' + temp
    }


    let candidate = keccak256(new Buffer(temp, 'hex'))
    let mynum = new BN(candidate, 16)

    let b = mynum.modn(2)

    mynum = mynum.shrn(1)

    mynum = mynum.toString(16)
    if (mynum.length < 64) {
      mynum = '0' + mynum
    }


    let res;
    try {
      res = decompress('0' + (b + 2).toString(10) + mynum)
      return res
    }
    catch (error) {
    }
  }
  return null
}


/**
 * Verify the correctness of the vrf calculation.
 */
function VRFVerify(m, e, z, pkPoint, outputPoint) {
  var msgPoint = MapOntoCurve(m)
  if (msgPoint == null) {
    throw new Error("Error : Max depth exceeded for mapping of message")
  }

  return VerifyDlogEqProof(e, [z], [getCurveGenerator(), msgPoint], [pkPoint, outputPoint])
}



/**
 * Verify the discrete logarithm equality on the elliptic curve.
 */
function VerifyDlogEqProof(_e, _zs, bases, powers) {
  let e = new BN(_e, 16)

  if (bases.length != powers.length) {
    return false
  }
  if (2 * _zs.length != bases.length) {
    return false
  }

  let negatede = getCurveOrder();
  negatede.isub(e);
  let toBeHashed = ''
  for (let index = 0; index < bases.length - 1; index = index + 2) {
    let z = _zs[index / 2]
    let znum = new BN(z, 16)
    let base1 = bases[index]
    let base2 = bases[index + 1]
    let pow1 = powers[index]
    let pow2 = powers[index + 1]

    let a1 = pow1.mul(negatede)
    let temp = base1.mul(znum)
    a1 = a1.add(temp)

    let a2 = pow2.mul(negatede)
    let temp2 = base2.mul(znum)
    a2 = a2.add(temp2)

    toBeHashed += pow1.encodeCompressed('hex') + pow2.encodeCompressed('hex') + a1.encodeCompressed('hex') + a2.encodeCompressed('hex')
  }


  let hashed = keccak256(new Buffer(toBeHashed, 'hex'))
  let eRecovered = new BN(hashed, 16)
  eRecovered = eRecovered.umod(getCurveOrder())
  let r = e.eq(eRecovered)

  return r
}


/**Recover the actual elliptic curve point from a compressed one.
 * 
 * @param  {string} point: a compressed point (in hexaecimal form)
 */
// function decompress(point) {
//   let isOdd = point.slice(0, 2) === '02'
//   let x = new BN(point.slice(2, 66), 16)
//   return ec.curve.pointFromX(x, !isOdd)

// }

function decompress(point){
    let isOdd = point.slice(0, 2) === '02'
    let x = new BN(point.slice(2, 66), 16)

    let y = x.mul(x).mul(x)
    y = y.add(b)
    y.mod(p)

    if(isOdd){
        y = p.sub(y)
    }

    return [x, y]
}

function decompress2(point){
  let isOdd = point.slice(0, 2) === '02'
  let x = new BN(point.slice(2, 66), 16)
}


/**
 * Verify the correctness of the party with input described below.
 */
function verify(ticket, publicKey, credential){
    let c = decompress(credential.slice(0, 66))
    let pubkey = decompress(publicKey)


    return VRFVerify(ticket.slice(0, 64), credential.slice(66, 130), credential.slice(130, 194), pubkey, c)

}

/**
 * Verify the correctness by using the POD.
 */
function verifyPOD(pod){
  let c = decompress(pod.credential.slice(0, 66))
  let pubkey = decompress(pod.publickey)

  return VRFVerify(pod.ticket.slice(0, 64), pod.credential.slice(66, 130), pod.credential.slice(130, 194), pubkey, c)
}


let isValid = verify(ticket, publicKey, credential)

console.log("The contribution is valid", isValid)


/**Use this method if you want to verify by using the whole JSON string.
 * See below for a sample input.
*/
// let data = '{"timestamp":"2019-11-21T10:45:41+08:00","publickey":"0300655927aa9dfa5a4d303debdd3acc62e11193c6a09410993f8d9ad35a95c6f7","credential":"036b5b6d70cb2b6108db6a1b157c9206970022508d28364f9777041875d88d9ff725f11709c78c6bdb092aaccf40853ad6400205ea19ede865222c14e34526f39e9ac3715ba00c1741541c7d6659651b5c9f68fb7fb1e8ad69f72a77d08d2032f2","ticket":"0000101100001011000010110000101100001011000010110000101100001011000001","contribution":"023045d435193f55e1637f8942aaa4c0b513529be1805762147f1da14231b531a1","signature":"57829fe78467d6b7f50d8ed5deb1804ebf607a4ba6b03e7bf4483d093a401d6ace05de2b36a2b82435901cd50d27ee0a2968838aad88a99ff8d15a4250da3704"}'
// let pod = JSON.parse(data);

// console.log(verifyPOD(pod))
