// https://www.npmjs.com/package/sha1
var sha1 = require('sha1');
// https://www.npmjs.com/package/big-integer
var bigInt = require("big-integer");

// Example
var checkum = sha1("message");
var zero = bigInt();
var ninetyThree = bigInt(93);
var largeNumber = bigInt("75643564363473453456342378564387956906736546456235345");
var googol = bigInt("1e100");
var bigNumber = bigInt(largeNumber); 
var maximumByte = bigInt("FF", 16);
var fiftyFiveGoogol = bigInt("<55>0", googol);

// TODO implement javascript library based on demo/javascript.html and bigint.js

module.exports = {
	// TODO
};