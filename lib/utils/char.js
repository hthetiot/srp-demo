/*
 * Modified by Tom Wu (tjw@cs.stanford.edu) for the
 * SRP JavaScript using Java implementation.
 */

/*
 * Modified by Harold Thetiot (hthetiot@gmail.com) for the
 * SRP JavaScript EcmaScript implementation.
 */

/*
 * Convert a 32-bit number to a hex string with ms-byte first
 */
var hex_chr = "0123456789abcdef";
exports.hex = function hex(num) {
  var str = "";
  for(var j = 7; j >= 0; j--)
    str += hex_chr.charAt((num >> (j * 4)) & 0x0F);
  return str;
};

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