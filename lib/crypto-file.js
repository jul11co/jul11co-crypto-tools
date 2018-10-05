// lib/crypto-file.js

var path = require('path');

var fse = require('fs-extra');
var chalk = require('chalk');
var bytes = require('bytes');

var utils = require('./utils');
var cryptor = require('./cryptor');

var PackFile = require('./pack-file');

var CryptoFile = function(file_path, encrypt_key) {
  this._path = file_path;
  this._enc_key = encrypt_key;
}

CryptoFile.prototype.load = function(options, done) {
  if (typeof options == 'function') {
    done = options;
    options = {};
  }

  var self = this;

  if (self._loaded) {
    return done();
  }

  if (options.read_only) self._read_only = true;

  self._pack_file = new PackFile({ path: self._path });
  self._tmp_dir = path.join(utils.getUserHome(), '.jul11co', 'crypto-tools', 'caches', utils.md5Hash(self._path));

  var _extractPackEntries = function(cb) {
    if (utils.fileExists(self._path)) {
      console.log('Reading existing cryptofile...');
      self._pack_file.extractEntries(['INDEX','VERSION','VERIFY'], self._tmp_dir, options, function(err, res) {
        if (err) {
          console.log('Reading existing cryptofile... Error!');
          return cb(err);
        } else {
          if (options.progress) console.log('Reading existing cryptofile... OK');
          return cb();
        }
      });
    } else {
      return cb();
    }
  }

  var _loadCryptoIndex = function(cb) {
    self._crypto_index = new cryptor.CryptoIndex(
      path.join(self._tmp_dir, 'INDEX'), 
      self._enc_key, 
      {
        debug: options.debug,
        obfuscate: options.obfuscate,
        read_only: options.read_only
      }
    );

    self._crypto_index.load(function(err) {
      if (err) {
        console.log('Load crypto index failed!');
        // console.log(err);
        if (err.message.indexOf('bad decrypt')!=-1) {
          err.message = 'Wrong passphrase';
        }
      } else {
        self._loaded = true;
      }

      cb(err);
    });
  }

  _extractPackEntries(function(err) {
    if (err) return done(err);
    return _loadCryptoIndex(done);
  });
}

CryptoFile.prototype.isLoaded = function() {
  return this._loaded;
}

CryptoFile.prototype.unload = function(options, done) {
  if (typeof options == 'function') {
    done = options;
    options = {};
  }

  var self = this;

  if (!self._loaded) {
    return done();
  }

  var _updateOrCreatePack = function(cb) {

    if (self._read_only) {
      return cb();
    }

    var pack_opts = {};
    if (options.progress) {
      pack_opts.onEntry = function(entry) {
        console.log((entry.type || 'File')[0], entry.path, chalk.magenta(bytes(entry.size)));
      }
    }

    if (utils.fileExists(self._path)) {
      console.log('Updating existing cryptofile...');
      self._pack_file.pack(self._tmp_dir, pack_opts, function(err, res) {
        if (err) {
          console.log('Updating existing cryptofile... Error!');
          return cb(err);
        } else {
          if (!options.debug) fse.removeSync(self._tmp_dir);
          var stats = utils.getFileStats(self._path);
          if (options.progress) console.log('Updating existing cryptofile... OK');
          console.log('Cryptopack updated:', self._path, chalk.magenta(stats ? bytes(stats['size']) : ''));
          return cb();
        }
      });
    } else {
      console.log('Creating new cryptofile...');
      self._pack_file.pack(self._tmp_dir, pack_opts, function(err, res) {
        if (err) {
          console.log('Creating new cryptofile... Error!');
          return cb(err);
        } else {
          if (!options.debug) fse.removeSync(self._tmp_dir);
          var stats = utils.getFileStats(self._path);
          if (options.progress) console.log('Creating new cryptofile... OK');
          console.log('Cryptopack created:', self._path, chalk.magenta(stats ? bytes(stats['size']) : ''));
          return cb();
        }
      });
    }
  }

  var _unloadCryptoIndex = function(cb) {
    if (!self._crypto_index) return cb();
    self._crypto_index.unload(function(err) {
      if (err) {
        console.log('Unload crypto index failed!');
        // console.log(err);
      } else {
        self._crypto_index = null;
        self._loaded = false;
      }
      
      cb(err);
    });
  }

  _unloadCryptoIndex(function(err) {
    if (err) return done(err);
    _updateOrCreatePack(done);
  })
}

CryptoFile.prototype.encode = function(INPUT_FILE, options, done) {

  var self = this;

  if (!self._loaded) {
    return self.load(options, function(err) {
      if (err) return done(err);
      self.encode(INPUT_FILE, options, done);
    });
  }

  // options.output_dir = self._tmp_dir;
  fse.ensureDirSync(self._tmp_dir);
  fse.emptyDirSync(self._tmp_dir);

  var pack_opts = {};
  if (typeof options.onEntry == 'function') {
    pack_opts.onEntry = options.onEntry;
  }

  var file_stat = utils.getStat(INPUT_FILE);
  if (!file_stat) {
    console.log('Cannot get file info!');
    return done(new Error('Cannot get file info!'));
  }

  var encrypted_file_name = 'DATA';
  var encrypted_file_path = path.join(self._tmp_dir, encrypted_file_name);

  fse.ensureDirSync(path.dirname(encrypted_file_path));

  if (options.progress) console.log('Encrypting file...');
  cryptor.encryptFile(INPUT_FILE, encrypted_file_path, self._enc_key, options, function(err) {
    if (err) {
      console.log('Encrypt file failed!');
      return done(err);
    } else {
      // add to crypto index
      self._crypto_index.put('DATA', {    
        p: path.basename(INPUT_FILE),  // path
        ep: encrypted_file_name,       // encrypted file path
        et: new Date(),                // encrypted time
        s: file_stat['size'],          // size
        m: file_stat['mode'],          // mode
        at: file_stat['atime'],        // atime
        mt: file_stat['mtime'],        // mtime
        ct: file_stat['ctime'],        // ctime
      });
      
      return done(null, {
        encrypted_file_stat: utils.getStat(encrypted_file_path)
      });
    }
  });
}

CryptoFile.prototype.decode = function(OUTPUT_FILE, options, done) {

  var self = this;

  if (!self._loaded) {
    return self.load(options, function(err) {
      if (err) return done(err);
      self.decode(OUTPUT_FILE, options, done);
    });
  }

  // fse.ensureDirSync(self._tmp_dir);
  fse.emptyDirSync(self._tmp_dir);

  var data_info = self._crypto_index.get('DATA');
  if (!data_info) {
    return done(new Error('Invalid cryptofile: Missing DATA!'));
  }

  var file = {
    encrypted: data_info.ep, 
    original: {
      path: data_info.p,
      size: data_info.s,
      mode: data_info.m,
      atime: data_info.at,
      mtime: data_info.mt,
      ctime: data_info.ct
    }
  };
  var orig_file = file.original;
  
  var extract_opts = {overwrite: true};
  if (typeof options.onEntry == 'function') {
    extract_opts.onEntry = options.onEntry;
  }

  self._pack_file.extractEntries([file.encrypted], extract_opts, function(err, result) {
    if (err) {
      console.log('Extract files failed!');
      console.log(err);
    } else {
      var encrypted_file_path = path.join(self._tmp_dir, file.encrypted);

      if (options.progress) console.log('Decrypting file...');
      cryptor.decryptFile(encrypted_file_path, OUTPUT_FILE, self._enc_key, options, function(err) {
        if (err) {
          console.log('Decrypt file error!');
          return done(err);
        } else {
          return done(null, {
            decrypted_file_stat: utils.getStat(OUTPUT_FILE)
          });
        }
      });
    }
  });
}

CryptoFile.prototype.info = function(options, done) {

  var self = this;

  if (!self._loaded) {
    return self.load(options, function(err) {
      if (err) return done(err);
      self.info(options, done);
    });
  }

  var data_info = self._crypto_index.get('DATA');
  if (!data_info) {
    return done(new Error('Invalid cryptofile: Missing DATA!'));
  }

  return done(null, {
    original_file: {
      path: data_info.p,
      size: data_info.s,
      mode: data_info.m,
      atime: data_info.at,
      mtime: data_info.mt,
      ctime: data_info.ct
    },
    encrypted_file_stat: utils.getStat(self._path)
  });
}

module.exports = CryptoFile;
