/*
 * Copyright (c) 1997-2003  The Stanford SRP Authentication Project
 * All Rights Reserved.
 * See http://srp.stanford.edu/license.txt for details.
 *
 * Any use of this software to demo cryptographic technology other
 * than SRP must include the following acknowledgement:
 * "This software incorporates components derived from the
 *  Secure Remote Password JavaScript demo developed by
 *  Tom Wu (tjw@CS.Stanford.EDU)."
 */

/*
 * Modified by Harold Thetiot (hthetiot@gmail.com) for the
 * SRP JavaScript EcmaScript implementation.
 */

/*
 * BigInteger glue layer:  If we need the applet (IE), access the various
 * java.math.BigInteger constructors through applet methods.  Otherwise
 * (Netscape) just refer to the java constructors directly.
 */

// Inject only if not supported
if (typeof global.bigInt == 'undefined') {
  // https://www.npmjs.com/package/big-integer
  var bigInt = require("big-integer");
}

// Inject only if not supported
if (typeof global.crypto == 'undefined') {
  // https://www.npmjs.com/package/crypto
  var crypto = require("crypto");
}

var utilsChar = require('./char');

function getRandomValues(buf) {
  if (crypto && crypto.getRandomValues) {
    return crypto.getRandomValues(buf);
  }
  if (typeof msCrypto === 'object' && typeof msCrypto.getRandomValues === 'function') {
    return msCrypto.getRandomValues(buf);
  }
  if (crypto.randomBytes) {
    if (!(buf instanceof Uint8Array)) {
      throw new TypeError('expected Uint8Array');
    }
    if (buf.length > 65536) {
      var e = new Error();
      e.code = 22;
      e.message = 'Failed to execute \'getRandomValues\' on \'Crypto\': The ' +
        'ArrayBufferView\'s byte length (' + buf.length + ') exceeds the ' +
        'number of bytes of entropy available via this API (65536).';
      e.name = 'QuotaExceededError';
      throw e;
    }
    var bytes = crypto.randomBytes(buf.length);
    buf.set(bytes);
    return buf;
  }
  else {
    throw new Error('No secure random number generator available.');
  }
}

/* Accepts radix as second argument */
exports.parseBigInt = function parseBigInt(str, r) {
  if(r == 64)
    return bigInt(utilsChar.b64tob8(str), 8);

  if(str.length === 0)
    str = "0";

  return bigInt(str, r);
};

/* Use toString() workaround if necessary */
exports.bigInt2StrHelper = function bigInt2StrHelper(bi, r) {
    return bi.toString(r);
};

exports.bigInt2radix = function bigInt2radix(bi, r) {
  if(r == 64)
    return utilsChar.b8tob64(String(exports.bigInt2StrHelper(bi, 8)));
  else
    return exports.bigInt2StrHelper(bi, r);
};

var rng = null;

/*
 * Select a random large integer with a given byte count.
 */
exports.randomBigInt = function randomBigInt(bytes) {
  var random_array = getRandomValues(new Uint8Array(bytes)); 
  var big_random = ""; 
  for(var i = 0; i < bytes; i++) { 
    var small_random = bigInt(random_array[i]).toString(2); 
    while(small_random.length < 32) { 
      small_random = "0" + small_random; 
    } 
    big_random += small_random; 
  } 
  return bigInt(big_random, 2); 
};

/* Returns a string with n zeroes in it */
exports.nzero = function nzero(n) {
    if (n < 1) {
        return "";
    }
    var t = nzero(n >> 1);
    if ((n & 1) === 0) {
        return t + t;
    } else {
        return t + t + "0";
    }
};
