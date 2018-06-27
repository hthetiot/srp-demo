/* jshint node: true */
'use strict';

// [START main_body]
var utilsBigInt = require('./utils/big-int');
var utilsSha = require('./utils/sha');

/*
var srp = new SrpClient();
srp.setPassword('password');
console.log(srp.data.srp_status);
*/
function SrpClient(opts) {

	var self = this;
	
	/* Internal state variables */
	var initialized = 0;
	var N = null;
	var g = null;
	var salt = null;
	var x = null;
	var x2 = null;
	var v = null;
	var a = null;
	var b = null;
	var A = null;
	var B = null;
	var u = null;
	var k = null;
	var Sc = null;
	var Ss = null;
	var status_string = "Initializing...";
	var one;
	var two;
	var three;
	var radix;
	var proto; // 3 or 6 or 6a

	var srp_data = {
		radixb: 16,
		protob: '6a',
		srp_N: '',
		srp_g: '2',
		params: 'eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3:2',
		srp_k: '',
		srp_username: 'user',
		srp_password: 'password',
		srp_salt: '',
		srp_x: '',
		srp_v: '',
		srp_a: '',
		srp_b: '',
		srp_A: '',
		srp_B: '',
		srp_password2: '',
		srp_u: '',
		srp_x2: '',
		srp_v2: '',
		srp_Sc: '',
		srp_Ss: '',
		srp_status: ''
	};

	function calcSHA1(data) {
		return utilsSha.calcSHA1(data);
	}

	function calcSHA1Hex(data) {
		return utilsSha.calcSHA1Hex(data);
	}

	/* The no-radix form uses the radix that is "in effect" for the whole page */
	function str2BigInt(str) {
	    return utilsBigInt.parseBigInt(str, radix);
	}

	function bigInt2Str(bi) {
	    return utilsBigInt.bigInt2radix(bi, radix);
	}

	/*
	 * SRP client/server helper functions.
	 * Most of the "nuts and bolts" of computing the various intermediate
	 * SRP values are in these functions.
	 */

	/* x = H(salt || H(username || ":" || password)) */
	function srp_compute_x(u, p, s) {
	    // Inner hash: SHA-1(username || ":" || password)
	    var ih = calcSHA1(u + ":" + p);
	    // Outer hash: SHA-1(salt || inner_hash)
	    // This assumes that the hex salt string has an even number of characters...
	    var oh = calcSHA1Hex(utilsBigInt.bigInt2radix(s, 16) + ih);
	    var xtmp = utilsBigInt.parseBigInt(oh, 16);
	    if (xtmp.compareTo(N) < 0) {
	        return xtmp;
	    } else {
	        return xtmp.mod(N.subtract(one));
	    }
	}

	/*
	 * SRP-3: u = first 32 bits (MSB) of SHA-1(B)
	 * SRP-6(a): u = SHA-1(A || B)
	 */
	function srp_compute_u(Nv, av, bv) {
	    var ahex;
	    var bhex = String(utilsBigInt.bigInt2radix(bv, 16));
	    var hashin = "";
	    var utmp;
	    var nlen;
	    if (proto !== "3") {
	        ahex = String(utilsBigInt.bigInt2radix(av, 16));
	        if (proto === "6") {
	            if ((ahex.length & 1) === 0) {
	                hashin += ahex;
	            } else {
	                hashin += "0" + ahex;
	            }
	        } else { /* 6a requires left-padding */
	            Nv.bitLength = function() {
	                return this.toString(2).length;
	            };
	            nlen = 2 * ((Nv.bitLength() + 7) >> 3);
	            hashin += utilsBigInt.nzero(nlen - ahex.length) + ahex;
	        }
	    }
	    if (proto === "3" || proto === "6") {
	        if ((bhex.length & 1) === 0) {
	            hashin += bhex;
	        } else {
	            hashin += "0" + bhex;
	        }
	    } else { /* 6a requires left-padding; nlen already set above */
	        hashin += utilsBigInt.nzero(nlen - bhex.length) + bhex;
	    }
	    if (proto == "3") {
	        utmp = utilsBigInt.parseBigInt(calcSHA1Hex(hashin).substr(0, 8), 16);
	    } else {
	        utmp = utilsBigInt.parseBigInt(calcSHA1Hex(hashin), 16);
	    }
	    if (utmp.compareTo(Nv) < 0) {
	        return utmp;
	    } else {
	        return utmp.mod(Nv.subtract(one));
	    }
	}

	function srp_compute_k(NN, gg) {
	    var hashin = "";
	    var nhex;
	    var ghex;
	    var ktmp;
	    if (proto == "3")
	        return one;
	    else if (proto == "6")
	        return three;
	    else {
	        /* SRP-6a: k = H(N || g) */
	        nhex = String(utilsBigInt.bigInt2radix(NN, 16));
	        if ((nhex.length & 1) === 0) {
	            hashin += nhex;
	        } else {
	            hashin += "0" + nhex;
	        }
	        ghex = String(utilsBigInt.bigInt2radix(gg, 16));
	        hashin += utilsBigInt.nzero(nhex.length - ghex.length);
	        hashin += ghex;
	        ktmp = utilsBigInt.parseBigInt(calcSHA1Hex(hashin), 16);
	        if (ktmp.compareTo(NN) < 0) {
	            return ktmp;
	        } else {
	            return ktmp.mod(NN);
	        }
	    }
	}

	/* S = (B - kg^x) ^ (a + ux) (mod N) */
	function srp_compute_client_S(BB, xx, uu, aa, kk) {
	    var bx = g.modPow(xx, N);
	    var btmp = BB.add(N.multiply(kk)).subtract(bx.multiply(kk)).mod(N);
	    return btmp.modPow(xx.multiply(uu).add(aa), N);
	}

	/* S = (Av^u) ^ b (mod N) */
	function srp_compute_server_S(AA, vv, uu, bb) {
	    return vv.modPow(uu, N).multiply(A).mod(N).modPow(bb, N);
	}

	function srp_validate_N() {
	    if (!N.isProbablePrime(10)) {
	        console.warn("Warning: N is not prime");
	        return false;
	    } else if (!N.subtract(one).divide(two).isProbablePrime(10)) {
	        console.warn("Warning: (N-1)/2 is not prime");
	        return false;
	    } else {
	        return true;
	    }
	}

	function srp_validate_g() {
	    if (g.modPow(N.subtract(one).divide(two), N).add(one).compareTo(N) !== 0) {
	        console.warn("Warning: g is not a primitive root");
	        return false;
	    } else {
	        return true;
	    }
	}

	/*
	 * isync_* methods: Synchronize internal state from form contents.
	 */

	function isync_radix() {
	    if (srp_data.radixb === 10) {
	        radix = 10;
	    } else if (srp_data.radixb === 64) {
	        radix = 64;
	    } else if (srp_data.radixb === 16) {
	        radix = 16;
	    } else {
	    	throw new Error('Invalid radix:' + srp_data.radixb);
	    }
	}

	function isync_proto() {
	    if (srp_data.protob === "3") {
	        proto = "3";
	    } else if (srp_data.protob === "6") {
	        proto = "6";
	    } else if (srp_data.protob === "6a") {
	        proto = "6a";
	    } else {
	    	throw new Error('Invalid proto:' + srp_data.protob);
	    }
	}

	function isync_params() {
	    var pstr = srp_data.params;
	    var si = pstr.indexOf(":");
	    N = utilsBigInt.parseBigInt(pstr.substr(0, si), 16);
	    g = utilsBigInt.parseBigInt(pstr.substr(si + 1), 16);
	    osync_g();
	    osync_N();
	}

	function isync_N() {
	    N = str2BigInt(srp_data.srp_N);
	}

	function isync_g() {
	    g = str2BigInt(srp_data.srp_g);
	}

	function isync_k() {
	    k = str2BigInt(srp_data.srp_k);
	}

	function isync_salt() {
	    salt = str2BigInt(srp_data.srp_salt);
	}

	function isync_x() {
	    x = str2BigInt(srp_data.srp_x);
	}

	function isync_x2() {
	    x2 = str2BigInt(srp_data.srp_x2);
	}

	function isync_v() {
	    v = str2BigInt(srp_data.srp_v);
	}

	function isync_v2() {
	    v = str2BigInt(srp_data.srp_v2);
	}

	function isync_a() {
	    a = str2BigInt(srp_data.srp_a);
	}

	function isync_b() {
	    b = str2BigInt(srp_data.srp_b);
	}

	function isync_A() {
	    A = str2BigInt(srp_data.srp_A);
	}

	function isync_B() {
	    B = str2BigInt(srp_data.srp_B);
	}

	function isync_u() {
	    u = str2BigInt(srp_data.srp_u);
	}

	function isync_Sc() {
	    Sc = str2BigInt(srp_data.srp_Sc);
	}

	function isync_Ss() {
	    Ss = str2BigInt(srp_data.srp_Ss);
	}

	function isync_status() {
	    status_string = srp_data.srp_status;
	}

	/*
	 * osync_* methods: Update form contents from internal state.
	 */
	function osync_N() {
	    srp_data.srp_N = bigInt2Str(N);
	}

	function osync_g() {
	    srp_data.srp_g = bigInt2Str(g);
	}

	function osync_k() {
	    srp_data.srp_k = bigInt2Str(k);
	}

	function osync_salt() {
	    srp_data.srp_salt = bigInt2Str(salt);
	}

	function osync_x() {
	    srp_data.srp_x = bigInt2Str(x);
	}

	function osync_x2() {
	    srp_data.srp_x2 = bigInt2Str(x2);
	}

	function osync_v() {
	    srp_data.srp_v = bigInt2Str(v);
	}

	function osync_v2() {
	    srp_data.srp_v2 = bigInt2Str(v);
	}

	function osync_a() {
	    srp_data.srp_a = bigInt2Str(a);
	}

	function osync_b() {
	    srp_data.srp_b = bigInt2Str(b);
	}

	function osync_A() {
	    srp_data.srp_A = bigInt2Str(A);
	}

	function osync_B() {
	    srp_data.srp_B = bigInt2Str(B);
	}

	function osync_u() {
	    srp_data.srp_u = bigInt2Str(u);
	}

	function osync_Sc() {
	    srp_data.srp_Sc = bigInt2Str(Sc);
	}

	function osync_Ss() {
	    srp_data.srp_Ss = bigInt2Str(Ss);
	}

	function osync_status() {
	    srp_data.srp_status = status_string;
	}

	/*
	 * Recalculation primitives: Recompute the internal state of a field,
	 * possibly based on changed values of other fields, and display the
	 * updated value in the form field value, usually via an osync() call.
	 * These are "endpoint" function calls, and are NOT responsible for
	 * propagating changes to dependent fields.
	 */

	function set_random_salt() {
	    salt = utilsBigInt.randomBigInt(10);
	    osync_salt();
	}

	function recalc_k() {
	    k = srp_compute_k(N, g);
	    osync_k();
	}

	function recalc_x() {
	    x = srp_compute_x(srp_data.srp_username, srp_data.srp_password, salt);
	    osync_x();
	}

	function recalc_x2() {
	    x2 = srp_compute_x(srp_data.srp_username, srp_data.srp_password2, salt);
	    osync_x2();
	}

	function recalc_v() {
	    v = g.modPow(x, N);
	    osync_v();
	    osync_v2();
	}

	function set_random_a() {
	    a = utilsBigInt.randomBigInt(32);
	    if (a.compareTo(N) >= 0) {
	        a = a.mod(N.subtract(one));
	    }
	    if (a.compareTo(two) < 0) {
	        a = two;
	    }
	    osync_a();
	}

	function set_random_b() {
	    b = utilsBigInt.randomBigInt(32);
	    if (b.compareTo(N) >= 0) {
	        b = b.mod(N.subtract(one));
	    }
	    if (b.compareTo(two) < 0) {
	        b = two;
	    }
	    osync_b();
	}

	function recalc_A() {
	    A = g.modPow(a, N);
	    osync_A();
	}

	function recalc_B() {
	    var bb = g.modPow(b, N);
	    B = bb.add(v.multiply(k)).mod(N);
	    osync_B();
	}

	function recalc_u() {
	    u = srp_compute_u(N, A, B);
	    osync_u();
	}

	function recalc_Sc() {
	    Sc = srp_compute_client_S(B, x2, u, a, k);
	    osync_Sc();
	}

	function recalc_Ss() {
	    Ss = srp_compute_server_S(A, v, u, b);
	    osync_Ss();
	}

	function recalc_status() {
	    if (Sc.compareTo(Ss) === 0) {
	        status_string = "Authentication succeeded";
	    } else {
	        status_string = "Authentication failed - try again";
	    }
	    osync_status();
	}

	/*
	 * update_* methods: The update() method for a field is called whenever
	 * that field's value is modified, and changes need to be propagated to
	 * dependent fields.  It is responsible for recomputing the values of
	 * directly dependent fields (usually via their recalc() functions), and
	 * then calling their update() methods, so that changes propagate to
	 * indirect dependencies.  update() methods should ideally be limited to
	 * calling other recalc() and update() functions.
	 */

	function update_params() {
	    recalc_k();
	    update_k();
	    recalc_x(); // Dependent because x is taken mod N-1.
	    update_x();
	    recalc_x2();
	    update_x2();
	    //recalc_v();
	    //update_v();
	    recalc_A();
	    update_A();

	    /* Redundant - these are all dependent on either v or A */
	    //recalc_B();
	    //update_B();
	    //recalc_Sc();
	    //update_Sc();
	    //recalc_Ss();
	    //update_Ss();
	}

	function update_k() {
	    recalc_B();
	    update_B();
	    //recalc_Sc();
	    //update_Sc();
	}

	function update_salt() {
	    recalc_x();
	    update_x();
	    recalc_x2();
	    update_x2();
	}

	function update_username() {
	    recalc_x();
	    update_x();
	    recalc_x2();
	    update_x2();
	}

	function update_password() {
	    recalc_x();
	    update_x();
	}

	function update_password2() {
	    recalc_x2();
	    update_x2();
	}

	function update_x() {
	    recalc_v();
	    update_v();
	}

	function update_x2() {
	    recalc_Sc();
	    update_Sc();
	}

	function update_v() {
	    recalc_B();
	    update_B();
	}

	function update_a() {
	    recalc_A();
	    update_A();
	    recalc_Sc();
	    update_Sc();
	}

	function update_b() {
	    recalc_B();
	    update_B();
	    recalc_Ss();
	    update_Ss();
	}

	function update_A() {
	    recalc_u(); // New for SRP-6
	    update_u();
	    recalc_Ss();
	    update_Ss();
	}

	function update_B() {
	    recalc_u();
	    update_u();
	    recalc_Sc();
	    update_Sc();
	}

	function update_u() {
	    recalc_Sc();
	    recalc_Ss();
	    update_Sc();
	    update_Ss();
	}

	function update_Sc() {
	    recalc_status();
	    update_status();
	}

	function update_Ss() {
	    recalc_status();
	    update_status();
	}

	function update_status() {}

	/*
	 * Event handlers: These are called directly as a result of some user
	 * action, like changing a form field or pushing a button.  These will
	 * usually call isync() to read in the field's new value, and then call
	 * the field's own update() to propagate changes.  Alternatively,
	 * the action might result in a new value computed internally, in which
	 * case the field is written out with osync() before update() is called.
	 */

	function set_radix(r) {
	    radix = r;
	    /* Call osync() for all fields affected by a radix change */
	    osync_N();
	    osync_g();
	    osync_k();
	    osync_salt();
	    osync_x();
	    osync_x2();
	    osync_v();
	    osync_v2();
	    osync_a();
	    osync_b();
	    osync_A();
	    osync_B();
	    osync_u();
	    osync_Sc();
	    osync_Ss();
	}

	function set_proto(p) {
	    proto = p;
	    recalc_k();
	    update_k();
	    //recalc_B();
	    //update_B();
	    recalc_u();
	    update_u();
	    recalc_Sc();
	    update_Sc();
	}

	function change_N() {
	    isync_N();
	    if (srp_validate_N()) {
	        srp_validate_g();
	    }
	    update_params();
	}

	function change_g() {
	    isync_g();
	    srp_validate_g();
	    update_params();
	}

	function change_params() {
	    isync_params();
	    update_params();
	}

	function change_k() {
	    isync_k();
	    update_k();
	}

	function randomize_salt() {
	    set_random_salt();
	    update_salt();
	}

	function change_salt() {
	    isync_salt();
	    update_salt();
	}

	function change_username() {
	    update_username();
	}

	function change_password() {
	    update_password();
	}

	function change_password2() {
	    update_password2();
	}

	function change_x() {
	    isync_x();
	    update_x();
	}

	function change_x2() {
	    isync_x2();
	    update_x2();
	}

	function change_v() {
	    isync_v();
	    osync_v2(); // Update the other one, too
	    update_v();
	}

	function change_v2() {
	    isync_v2();
	    osync_v(); // Update the other one, too
	    update_v();
	}

	function randomize_a() {
	    set_random_a();
	    update_a();
	}

	function change_a() {
	    isync_a();
	    update_a();
	}

	function randomize_b() {
	    set_random_b();
	    update_b();
	}

	function change_b() {
	    isync_b();
	    update_b();
	}

	function change_A() {
	    isync_A();
	    update_A();
	}

	function change_B() {
	    isync_B();
	    update_B();
	}

	function change_u() {
	    isync_u();
	    update_u();
	}

	function change_Sc() {
	    isync_Sc();
	    update_Sc();
	}

	function change_Ss() {
	    isync_Ss();
	    update_Ss();
	}

	/*
	 * Initialization - make sure all fields get populated, and that
	 * internal state is consistent.
	 */
	function srp_initialize() {
	    if (initialized > 0)
	        return;
	    one = utilsBigInt.parseBigInt("1", 16);
	    two = utilsBigInt.parseBigInt("2", 16);
	    three = utilsBigInt.parseBigInt("3", 16);
	    isync_radix();
	    isync_proto();
	    if (srp_data.srp_N === "" || srp_data.srp_g === "") {
	        isync_params();
	    } else {
	        isync_N();
	        isync_g();
	    }
	    if (srp_data.srp_salt === "") {
	        set_random_salt();
	    } else {
	        isync_salt();
	    }
	    if (srp_data.srp_a === "") {
	        set_random_a();
	    } else {
	        isync_a();
	    }
	    if (srp_data.srp_b === "") {
	        set_random_b();
	    } else {
	        isync_b();
	    }
	    recalc_k();
	    recalc_x();
	    recalc_x2();
	    recalc_v();
	    recalc_A();
	    recalc_B();
	    recalc_u();
	    recalc_Sc();
	    recalc_Ss();
	    recalc_status();

	    initialized = 1;
	}

	return Object.create(null, {
		data: {
			get: function () {
				return srp_data;
			}
		},
		initialize: {
			value: srp_initialize
		},
		setPassword: {
			value: function (password) {

				if (!initialized) {
					srp_initialize();
				}

				srp_data.srp_password2 = password;
				change_password2();
			}
		}
	});
}

exports.SrpClient = SrpClient;
// [END main_body]
