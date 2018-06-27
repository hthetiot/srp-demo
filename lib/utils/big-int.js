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
  // https://www.npmjs.com/package/big-integer
  var crypto = require("crypto");
}

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

var b64_chr = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./";
exports.b64tob8 = function b64tob8(str) {
  var ret = "";
  var d;
  for(var j = 0; j < str.length; ++j) {
    d = b64_chr.indexOf(str.charAt(j));
    ret += hex_chr.charAt((d >> 3) & 7);
    ret += hex_chr.charAt(d & 7);
  }
  return ret;
};

exports.b8tob64 = function b8tob64(str) {
  var ret = "";
  var j = 0;
  if((str.length & 1) > 0) {
    ret += str.charAt(0);
    j = 1;
  }
  while(j < str.length) {
    ret += b64_chr.charAt(parseInt(str.substr(j, 2), 8));
    j += 2;
  }
  return ret;
};

/* Accepts radix as second argument */
exports.parseBigInt = function parseBigInt(str, r) {
  if(r == 64)
    return bigInt(b64tob8(str), 8);

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
    return exports.b8tob64(String(exports.bigInt2StrHelper(bi, 8)));
  else
    return exports.bigInt2StrHelper(bi, r);
};

/*
 * Convert an 8-bit number to its two-character hex representation.
 * (hex_chr is defined in sha1.js)
 */
exports.hex_byte = function hex_byte(num) {
  return hex_chr.charAt((num >> 4) & 0x0F) + hex_chr.charAt(num & 0x0F);
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
