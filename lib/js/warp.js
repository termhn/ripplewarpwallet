'use strict';

var _regenerator = require('babel-runtime/regenerator');

var _regenerator2 = _interopRequireDefault(_regenerator);

var _promise = require('babel-runtime/core-js/promise');

var _promise2 = _interopRequireDefault(_promise);

var _asyncToGenerator2 = require('babel-runtime/helpers/asyncToGenerator');

var _asyncToGenerator3 = _interopRequireDefault(_asyncToGenerator2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var _require = require('triplesec'),
    scrypt = _require.scrypt,
    pbkdf2 = _require.pbkdf2,
    HMAC_SHA256 = _require.HMAC_SHA256,
    WordArray = _require.WordArray,
    util = _require.util;

var _require2 = require('ripple-keypairs'),
    generateSeed = _require2.generateSeed,
    deriveKeypair = _require2.deriveKeypair,
    deriveAddress = _require2.deriveAddress;

var params = require('../json/params.json');

//=====================================

var from_utf8 = function from_utf8(s, i) {
  var b = new Buffer(s, 'utf8');
  var b2 = Buffer.concat([b, new Buffer([i])]);
  var ret = WordArray.from_buffer(b2);
  util.scrub_buffer(b);
  util.scrub_buffer(b2);
  return ret;
};

module.exports = function () {
  var _ref2 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee(_ref, cb) {
    var passphrase = _ref.passphrase,
        salt = _ref.salt,
        progress_hook = _ref.progress_hook;
    var scrypt_params, s1, pbkdf2_params, s2, user_seed_final, garbage, seed, out;
    return _regenerator2.default.wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            scrypt_params = {
              N: params.N,
              p: params.p,
              r: params.r,
              dkLen: params.dkLen,
              pbkdf2c: params.pbkdf2c,
              key: from_utf8(passphrase, 1),
              salt: from_utf8(salt, 1),
              progress_hook: progress_hook
            };
            _context.next = 3;
            return new _promise2.default(function (res, rej) {
              return scrypt(scrypt_params, res);
            });

          case 3:
            s1 = _context.sent;
            pbkdf2_params = {
              key: from_utf8(passphrase, 2),
              salt: from_utf8(salt, 2),
              c: params.pbkdf2c,
              dkLen: params.dkLen,
              progress_hook: progress_hook,
              klass: HMAC_SHA256
            };
            _context.next = 7;
            return new _promise2.default(function (res, rej) {
              return pbkdf2(pbkdf2_params, res);
            });

          case 7:
            s2 = _context.sent;


            s1.xor(s2, {});

            user_seed_final = s1.to_buffer();
            garbage = [s1, s2, scrypt_params.key, pbkdf2_params.key];

            garbage.forEach(function (obj) {
              return obj.scrub();
            });

            seed = generateSeed({ entropy: user_seed_final });
            out = deriveKeypair(seed);

            out.secret = seed;
            out.address = deriveAddress(out.publicKey);
            cb(out);

          case 17:
          case 'end':
            return _context.stop();
        }
      }
    }, _callee, this);
  }));

  return function (_x, _x2) {
    return _ref2.apply(this, arguments);
  };
}();
