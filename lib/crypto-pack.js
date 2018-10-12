// lib/crypto-pack.js

var fs = require('fs');
var path = require('path');

var fse = require('fs-extra');
var bytes = require('bytes');

var log = require('single-line-log').stdout;

var utils = require('./utils');
var cryptor = require('./cryptor');
var crypto_mount = require('./crypto-mount');

var PackFile = require('./pack-file');

var CryptoPack = function(pack_path, encrypt_key) {
	this._path = pack_path;
	this._enc_key = encrypt_key;
  this._entries_map = {};
}

CryptoPack.prototype.load = function(options, done) {
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
      console.log('Reading existing cryptopack...');
      self._pack_file.extractEntries(['INDEX','VERSION','VERIFY'], self._tmp_dir, options, function(err, res) {
        if (err) {
          console.log('Reading existing cryptopack... Error!');
          return cb(err);
        } else {
          if (options.progress) console.log('Reading existing cryptopack... OK');
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

CryptoPack.prototype.isLoaded = function() {
  return this._loaded;
}

CryptoPack.prototype.unload = function(options, done) {
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
    if (typeof options.onEntry == 'function') {
      pack_opts.onEntry = options.onEntry;
    }

    if (utils.fileExists(self._path)) {
      console.log('Updating existing cryptopack...');
      self._pack_file.pack(self._tmp_dir, pack_opts, function(err, res) {
        if (err) {
          console.log('Updating existing cryptopack... Error!');
          return cb(err);
        } else {
          if (!options.debug) fse.removeSync(self._tmp_dir);
          return cb(null, {updated: true, stats: utils.getFileStats(self._path)});
        }
      });
    } else {
      console.log('Creating new cryptopack...');
      self._pack_file.pack(self._tmp_dir, pack_opts, function(err, res) {
        if (err) {
          console.log('Creating new cryptopack... Error!');
          return cb(err);
        } else {
          if (!options.debug) fse.removeSync(self._tmp_dir);
          return cb(null, {created: true, stats: utils.getFileStats(self._path)});
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

CryptoPack.prototype.pack = function(INPUT_DIR, options, done) {

	var self = this;

  if (!self._loaded) {
    return self.load(options, function(err) {
      if (err) return done(err);
      self.pack(INPUT_DIR, options, done);
    });
  }

  options.output_dir = self._tmp_dir;
  fse.ensureDirSync(self._tmp_dir);
  fse.emptyDirSync(self._tmp_dir);

  cryptor.encryptDir(INPUT_DIR, self._tmp_dir, self._enc_key, self._crypto_index, options, function(err, result) {
    done(err, result);
  });
}

CryptoPack.prototype.extract = function(OUTPUT_DIR, options, done) {

	var self = this;

  if (!self._loaded) {
    return self.load(options, function(err) {
      if (err) return done(err);
      self.extract(OUTPUT_DIR, options, done);
    });
  }

  fse.ensureDirSync(OUTPUT_DIR);
  fse.emptyDirSync(self._tmp_dir);

  self._crypto_index.getFileList(function(err, _files) {

    if (options.extract_entries && options.extract_entries.length) {
      _files = _files.filter(function(file_info) {
        return options.extract_entries.some(function(entry) {
          return (file_info.path.indexOf(entry) == 0);
        });
      });
    }

    var entries = files.map(function(file_info) {
      return path.join(file_info.hash[0], file_info.hash[1], file_info.hash[2], file_info.hash);
    });

    var extract_opts = {overwrite: true};
    if (entries.length) {
      extract_opts.entries = entries;
    }
    if (typeof options.onEntry == 'function') {
      extract_opts.onEntry = options.onEntry;
    }

    self._pack_file.extract(self._tmp_dir, extract_opts, function(err, result) {
      if (err) {
        console.log('Extract files failed!');
        return done(err);
      } else {
        // decrypt extracted folder
        cryptor.decryptDir(self._tmp_dir, OUTPUT_DIR, self._enc_key, self._crypto_index, options, function(err, result) {
          return done(err, result);
        });
      }
    });
  }); // crypto_index.getFileList

}

CryptoPack.prototype.list = function(options, done) {

	var self = this;

  if (!self._loaded) {
    return self.load(options, function(err) {
      if (err) return done(err);
      self.list(options, done);
    });
  }

  var count = 0;
  var total_size = 0;

  var largest_size = 0;
  var largest_file = {};

  self._crypto_index.getFileList(function(err, _files) {

    if (options.list_entries && options.list_entries.length) {
      _files = _files.filter(function(file_info) {
        return options.list_entries.some(function(entry) {
          return (file_info.path.indexOf(entry) == 0);
        });
      });
    }

    _files.forEach(function(file_info) {
      count++;
      if (typeof options.onFileInfo == 'function') {
        options.onFileInfo(file_info, count);
      }
      
      total_size += file_info.size;
      if (file_info.size > largest_size) {
        largest_size = file_info.size;
        largest_file = { path: file_info.path, size: file_info.size };
      }
    });

    return done(null, {
      count: count,
      total_size: total_size,
      largest_size: largest_size,
      largest_file: largest_file
    });
  });
}

CryptoPack.prototype.index = function(options, done) {

	var self = this;

  if (!self._loaded) {
    return self.load(options, function(err) {
      if (err) return done(err);
      self.index(options, done);
    });
  }

  var index_opts = {overwrite: true};
  if (typeof options.onEntry == 'function') {
    index_opts.onEntry = options.onEntry;
  }

  if (options.progress) console.log('Generating index...');
  var start_time = new Date();

  self._pack_file.createIndex(index_opts, function(err) {
    if (err) {
      console.log('Generating index... Error!');
      // console.log(err);
      return done(err);
    }

    if (options.progress) console.log('Generating index... Done');

    var result = {
      index_time: new Date()-start_time,
      index_stats: self._pack_file.getIndexStats()
    };

    var idx_file = options.index_file || self._path + '.idx';
    self._pack_file.saveIndex(idx_file, function(err) {
      if (err) {
        console.log('Saving index to file... Error!');
        // console.log(err);
        return done(err);
      }

      if (options.progress) console.log('Saving index to file... Done');

      result.index_file_stats = utils.getStat(idx_file);

      return done(null, result);
    });
  });
}

var getParentDirs = function(_path, opts) {
  opts = opts || {};

  var parents = [];
  var parent = path.dirname(_path);
  
  if (opts.trailing_slash) parent = parent + '/';
  if (parent && parent != '' && parent != '.' && parent != './') {
    var _parents = getParentDirs(parent, opts);
    if (_parents.length) parents = parents.concat(_parents);
    parents.push(parent);
  }
  
  return parents;
}

CryptoPack.prototype.listPack = function(opts, callback) {
  if (typeof opts == 'function') {
    callback = opts;
    opts = {};
  }

  var self = this;

  var result = {
    entries: [],
    totalSize: 0
  }

  self._crypto_index.getFileList(function(err, _files) {
    
    _files.forEach(function(file_info) {
      var entry = Object.assign(file_info, {type: 'file'});
      self._entries_map[entry.path] = entry;
      
      // add entries for parent dirs (if not added)
      var dirs = getParentDirs(entry.path);
      if (dirs.length) {
        dirs.forEach(function(dir_relpath) {
          if (!self._entries_map[dir_relpath]) {
            self._entries_map[dir_relpath] = {
              type: 'directory',
              path: dir_relpath,
              size: 0,
              mtime: entry.mtime
            }
          } else if (self._entries_map[dir_relpath].mtime < entry.ctime) {
            self._entries_map[dir_relpath].mtime = entry.ctime;
          }
        });
      }
    });

    for (var entry_path in self._entries_map) {
      var entry = self._entries_map[entry_path];
      result.totalSize += entry.size;
      result.entries.push(entry);
    }

    return callback(null, result);
  });
}

CryptoPack.prototype.extractEntry = function(fpath, output_dir, opts, callback) {
  if (typeof opts == 'function') {
    callback = opts;
    opts = {};
  }

  var self = this;

  if (!self._entries_map[fpath] || !self._entries_map[fpath].encrypted_path) {
    return callback(new Error('Entry not found: ' + fpath));
  }

  var entry = self._entries_map[fpath];
  var encrypted_file_abs_path = path.join(self._tmp_dir, entry.encrypted_path);

  // console.log('extractEntry:', fpath);

  self._pack_file.extractEntry(entry.encrypted_path, self._tmp_dir, function(err) {
    if (err) return callback(err);
    if (!utils.fileExists(encrypted_file_abs_path)) {
      return callback(new Error('File not extracted:', encrypted_file_abs_path));
    }

    var decrypted_file_abs_path = path.join(DECRYPTED_TMP_DIR, entry.path);
    fse.ensureDirSync(path.dirname(decrypted_file_abs_path));

    cryptor.decryptFile(encrypted_file_abs_path, decrypted_file_abs_path, self._enc_key, function(err) {
      if (err) {
        console.log('Decrypt file failed!', encrypted_file_abs_path);
        return callback(err);
      }
      if (!utils.fileExists(decrypted_file_abs_path)) {
        return callback(new Error('File not decrypted:', encrypted_file_abs_path));
      }

      var entry_mtime = new Date(entry.mtime).getTime()/1000;
      try {
        fs.utimesSync(decrypted_file_abs_path, new Date(), entry_mtime);
      } catch(e) {
        console.log(e);
      }

      return callback();
    });
  })
}

CryptoPack.prototype.browse = function(options, done) {

	var self = this;

  if (!self._loaded) {
    return self.load(options, function(err) {
      if (err) return done(err);
      self.browse(options, done);
    });
  }

  // fse.ensureDirSync(self._tmp_dir);
  fse.emptyDirSync(self._tmp_dir);

  var DECRYPTED_TMP_DIR = path.join(self._tmp_dir, '_DECRYPTED');

  process.on('exit', function() {
    fse.emptyDirSync(DECRYPTED_TMP_DIR);
  });

  var browser_opts = {};

  var crypto_source = {
    path: self._path,
    listEntry: self.listPack.bind(self),
    getEntry: self.extractEntry.bind(self)
  };

  require('./crypto-browser')(crypto_source, DECRYPTED_TMP_DIR, browser_opts, done);
}

CryptoPack.prototype.mount = function(MOUNT_POINT, options, done) {

	var self = this;

  if (!self._loaded) {
    return self.load(options, function(err) {
      if (err) return done(err);
      self.mount(MOUNT_POINT, options, done);
    });
  }

  // fse.ensureDirSync(self._tmp_dir);
  fse.emptyDirSync(self._tmp_dir);

  var DECRYPTED_TMP_DIR = path.join(self._tmp_dir, '_DECRYPTED');
  // options.tmp_dir = DECRYPTED_TMP_DIR;

  process.on('exit', function() {
    fse.emptyDirSync(DECRYPTED_TMP_DIR);
  });

  if (!utils.directoryExists(MOUNT_POINT)) {
    fse.ensureDirSync(MOUNT_POINT);
  }

  var crypto_source = {
    path: self._path,
    list: self.listPack.bind(self),
    getEntry: self.extractEntry.bind(self)
  };

  var mount_point = new crypto_mount.MountPoint(crypto_source, MOUNT_POINT, DECRYPTED_TMP_DIR, options);
  mount_point.mount(function(err) {
    if (err) {
      return done(err);
    }
    return done(null, mount_point);
  });
}

module.exports = CryptoPack;
