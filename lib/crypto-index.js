// lib/crypto-index.js

var fs = require('fs');
var path = require('path');
var util = require('util');
var crypto = require('crypto');

var async = require('async');
var fse = require('fs-extra');
var chalk = require('chalk');
var bytes = require('bytes');

var utils = require('./utils');
var cryptor = require('./cryptor');

var crypto_config_dir = path.join(utils.getUserHome(), '.jul11co', 'crypto-tools');
var crypto_tmp_dir = path.join(crypto_config_dir, 'tmp');
// fse.ensureDirSync(crypto_tmp_dir);

var CryptoIndex = function(index_path, enc_key, options) {
  if (typeof index_path == 'object') {
    options = index_path;
    this._path = options['path'] || options['index_path'];
    this._encrypt_key = options['encrypt_key'];
  } else {
    this._path = index_path;
  }
  if (typeof enc_key == 'object') {
    options = enc_key;
    this._encrypt_key = options['encrypt_key'];
  } else {
    this._encrypt_key = enc_key;
  }

  this._tmp_dir = path.join(crypto_tmp_dir, utils.md5Hash(this._path));

  this._loaded = false;
  
  this._files_map = {};

  this._verify_string = options.verify_string || 'jul11co-crypto-index';
  this._obfuscate = options.obfuscate;

  this._debug = options.debug;
  this._read_only = options.read_only;

  this._version = cryptor.VERSION;
}

CryptoIndex.prototype.version = function() {
  return this._version;
}
CryptoIndex.prototype.getVersion = function() {
  return this._version;
}

CryptoIndex.prototype._loadVersionFile = function() {
  var version_file = path.join(path.dirname(this._path), 'VERSION');
  if (utils.fileExists(version_file)) {
    try {
      this._version = fs.readFileSync(version_file, {encoding: 'utf8'});
    } catch(e) {
      console.log(e);
    }
  }
}

CryptoIndex.prototype._writeVersionFile = function() {
  var version_file = path.join(path.dirname(this._path), 'VERSION');
  if (!utils.fileExists(version_file)) { // Do not alter existing VERSION file
    fs.writeFileSync(version_file, this._version, {encoding: 'utf8'});
  }
}

CryptoIndex.prototype.obfuscate = function() {
  return this._obfuscate;
}
CryptoIndex.prototype.isObfuscated = function() {
  return this._obfuscate;
}

CryptoIndex.prototype._loadObfuscateFile = function() {
  var obfuscate_file = path.join(path.dirname(this._path), 'OBFUSCATE');
  if (utils.fileExists(obfuscate_file)) {
    try {
      var obfuscate = fs.readFileSync(obfuscate_file, {encoding: 'utf8'});
      if (obfuscate == 'true') {
        this._obfuscate = true;
      }
    } catch(e) {
      console.log(e);
    }
  }
}

CryptoIndex.prototype._writeObfuscateFile = function() {
  var obfuscate_file = path.join(path.dirname(this._path), 'OBFUSCATE');
  if (!utils.fileExists(obfuscate_file) && this._obfuscate) { // Do not alter existing OBFUSCATE file
    fs.writeFileSync(obfuscate_file, this._obfuscate, {encoding: 'utf8'});
  }
}

CryptoIndex.prototype.getVerifyString = function() {
  return this._verify_string;
}

CryptoIndex.prototype._loadVerifyFile = function() {
  var verify_file = path.join(path.dirname(this._path), 'VERIFY');
  if (utils.fileExists(verify_file)) {
    this._verify_file_exists = true;
    this._encrypted_verify_string = fs.readFileSync(verify_file, {encoding: 'utf8'});
  }
}

CryptoIndex.prototype._writeVerifyFile = function() {
  var verify_file = path.join(path.dirname(this._path), 'VERIFY');
  if (!utils.fileExists(verify_file)) { // Do not alter existing VERIFY file
    var encrypted_verify_string = cryptor.encryptString(this._verify_string, this._encrypt_key);
    fs.writeFileSync(verify_file, encrypted_verify_string, {encoding: 'utf8'});
  }
}

CryptoIndex.prototype._encryptIndexFile = function(done) {
  var self = this;

  var tmp_uncrypted_file_name = (self._debug) ? 'index-debug-unload.json' : 'index.json';
  // var tmp_uncrypted_file = path.join(path.dirname(self._path), tmp_uncrypted_file_name);
  var tmp_uncrypted_file = path.join(self._tmp_dir, tmp_uncrypted_file_name);
  var tmp_index_file = path.join(self._tmp_dir, 'INDEX');

  utils.saveToJsonFile(self._files_map, tmp_uncrypted_file);

  cryptor.encryptFile(tmp_uncrypted_file, tmp_index_file, self._encrypt_key, function(err) {
    if (err) {
      return done(err);
    }

    fse.copy(tmp_index_file, self._path, {
      overwrite: true,
      preserveTimestamps: true
    }, function(err) {
      if (!self._debug) fse.removeSync(tmp_uncrypted_file);
      return done();
    });
  });
}

CryptoIndex.prototype._decryptIndexFile = function(done) {
  var self = this;

  var time = (new Date()).getTime();
  var tmp_index_file = path.join(self._tmp_dir, 'INDEX-'+time);
  var tmp_decrypted_file_name = (self._debug) ? 'index-debug-load.json' : 'index.json';
  // var tmp_decrypted_index_file = path.join(path.dirname(self._path), tmp_decrypted_file_name);
  var tmp_decrypted_index_file = path.join(self._tmp_dir, tmp_decrypted_file_name);

  fse.copy(self._path, tmp_index_file, {
    overwrite: true,
    preserveTimestamps: true
  }, function(err) {
    if (err) {
      return done(err);
    }

    cryptor.decryptFile(tmp_index_file, tmp_decrypted_index_file, self._encrypt_key, function(err) {
      if (err) {
        return done(err);
      }
      self._files_map = utils.loadFromJsonFile(tmp_decrypted_index_file);
      if (!self._debug) fse.removeSync(tmp_decrypted_index_file);
      return done();
    });
  });
}

CryptoIndex.prototype.verify = function(done) {
  var self = this;

  self._loadVerifyFile();

  if (self._encrypted_verify_string) {
    try {
      var verify_string = cryptor.decryptString(self._encrypted_verify_string, self._encrypt_key);
      if (self._verify_string != verify_string) {
        return done(new Error('Invalid encryption key!'));
      }
    } catch(e) {
      // console.log('Verify failed! ' + e.message);
      return done(e);
    }
  } else if (this._verify_file_exists) {
    return done(new Error('Missing verify string, unable to verify encryption key!'));
  }
  
  return done();
}

CryptoIndex.prototype.load = function(done) {
  var self = this;

  if (self._loaded) {
    return done();
  }

  fse.ensureDirSync(this._tmp_dir);

  self._loadVersionFile();
  self._loadObfuscateFile();

  self._files_map = {};

  self.verify(function(err) {
    if (err) return done(err);

    if (utils.fileExists(self._path)) {
      // console.log('Load:', self._path);
      self._decryptIndexFile(function(err) {
        if (err) return done(err);
        self._loaded = true;
        return done();
      });
    } else {
      self._loaded = true;
      return done();
    }
  });
}

CryptoIndex.prototype.loaded = function(done) {
  return this._loaded;
}
CryptoIndex.prototype.isLoaded = function(done) {
  return this._loaded;
}

CryptoIndex.prototype.unload = function(done) {
  var self = this;

  if (!self._loaded) {
    return done();
  }

  if (self._read_only) {
    self._loaded = false;
    self._files_map = {}; // clear files map
    return done();
  }

  self._writeVersionFile();
  self._writeObfuscateFile();

  self._writeVerifyFile();

  // console.log('Unload:', self._path);
  self._encryptIndexFile(function(err) {
    if (err) return done(err);
    self._loaded = false;
    self._files_map = {}; // clear files map
    return done();
  });
}

CryptoIndex.prototype.map = function() {
  return this._files_map;
}

CryptoIndex.prototype.put = function(key, value) {
  this._files_map[key] = value;
}

CryptoIndex.prototype.get = function(key) {
  return this._files_map[key];
}

CryptoIndex.prototype.hasKey = function(key) {
  return (typeof this._files_map[key] != 'undefined');
}

CryptoIndex.prototype.remove = function(key) {
  delete this._files_map[key];
}

module.exports = CryptoIndex;

