// lib/cryptor.js

var fs = require('fs');
var path = require('path');
var util = require('util');
var crypto = require('crypto');

var async = require('async');
var fse = require('fs-extra');
var chalk = require('chalk');
var bytes = require('bytes');

var utils = require('./utils');

var CryptoIndex = require('./cryptoindex');

var VERSION = '0.0.4';

exports.VERSION = VERSION;

exports.getVersion = function() {
  return VERSION;
}

////

exports.CryptoIndex = CryptoIndex;

////

var _encryptString = function(input_string, key, options) {
  options = options || {};
  var key_buf = new Buffer(key);
  var cipher = crypto.createCipher(options.algorithm || 'aes192', key_buf);
  var crypted = cipher.update(input_string,'utf8','hex');
  crypted += cipher.final('hex');
  return crypted;
}

var _decryptString = function(input_string, key, options) {
  options = options || {};
  var key_buf = new Buffer(key);
  var decipher = crypto.createDecipher(options.algorithm || 'aes192', key_buf);
  var decrypted = decipher.update(input_string,'hex','utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

var _encryptFile = function(input_file, output_file, key, options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }

  if (options.obfuscate && options.remove_source_files) {
    return fse.move(input_file, output_file, function(err) {
      if (err) return callback(err);
      callback();
    });
  } else if (options.obfuscate) {
    return fse.copy(input_file, output_file, function(err) {
      if (err) return callback(err);
      callback();
    });
  }
  
  var key_buf = new Buffer(key);

  var input_stream = fs.createReadStream(input_file);
  var output_stream = fs.createWriteStream(output_file);
  var cipher = crypto.createCipher(options.algorithm || 'aes192', key_buf);

  input_stream.on('data', function(data) {
    var buf = new Buffer(cipher.update(data), 'binary');
    output_stream.write(buf);
  });

  input_stream.on('end', function() {
    try {
      var buf = new Buffer(cipher.final('binary'), 'binary');
      output_stream.write(buf);
      output_stream.end();
      output_stream.on('close', function() {
        return callback();
      });
    } catch(e) {
      fs.unlink(output_file);
      return callback(e);
    }
  });
}

var _decryptFile = function(input_file, output_file, key, options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }

  if (options.obfuscate && options.remove_encrypted_files) {
    return fse.move(input_file, output_file, function(err) {
      if (err) return callback(err);
      callback();
    });
  } else if (options.obfuscate) {
    return fse.copy(input_file, output_file, function(err) {
      if (err) return callback(err);
      callback();
    });
  }

  var key_buf = new Buffer(key);

  var input_stream = fs.createReadStream(input_file);
  var output_stream = fs.createWriteStream(output_file);
  var decipher = crypto.createDecipher(options.algorithm || 'aes192', key_buf);

  input_stream.on('data', function(data) {
    var buf = new Buffer(decipher.update(data), 'binary');
    output_stream.write(buf);
  });

  input_stream.on('end', function() {
    try {
      var buf = new Buffer(decipher.final('binary'), 'binary');
      output_stream.write(buf);
      output_stream.end();
      output_stream.on('close', function() {
        return callback();
      });
    } catch(e) {
      fs.unlink(output_file);
      return callback(e);
    }
  });
}

exports.encryptString = _encryptString;
exports.decryptString = _decryptString;
exports.encryptFile = _encryptFile;
exports.decryptFile = _decryptFile;

////

var dir_hash_map = {};

var getDirHashedPath = function(dir_rel_path, encryption_key) {
  if (!dir_rel_path || dir_rel_path == '') return '';

  if (dir_hash_map[dir_rel_path]) {
    return dir_hash_map[dir_rel_path];
  }
  
  var result_path_parts = [];
  var path_sep = path.sep; // Mac & Linux ('/'), Windows ('\')
  var path_parts = dir_rel_path.split(path_sep); 
  
  for (var i = 0; i < path_parts.length; i++) {
    var dir_p = (i==0) ? path_parts[0] : path_parts.slice(0, i).join(path_sep);
    if (!dir_hash_map[dir_p]) {
      dir_hash_map[dir_p] = utils.md5Hash(dir_p);
      // dir_hash_map[dir_p] = _encryptString(dir_p, encryption_key);
    }
    result_path_parts.push(dir_hash_map[dir_p]);
  }

  return result_path_parts.join(path_sep);
}

var getFileHashedPath = function(file_rel_path, encryption_key, opts) {
  opts = opts || {};
  // calculate file's hashed path
  var file_hashed_name = utils.md5Hash(file_rel_path);
  // var file_hashed_name = _encryptString(file_rel_path, encryption_key);
  var file_hashed_rel_path = '';
  if (opts.keep_structure) {
    var dir_name = path.dirname(file_rel_path);
    if (dir_name == '.') {
      file_hashed_rel_path = path.join('DATA', file_hashed_name);
    } else {
      var dir_hashed_path = getDirHashedPath(dir_name, encryption_key);
      file_hashed_rel_path = path.join('DATA', dir_hashed_path, file_hashed_name);
    }
  } else {
    file_hashed_rel_path = path.join('DATA', file_hashed_name[0], 
      file_hashed_name[1] + file_hashed_name[2], file_hashed_name);
  }
  return file_hashed_rel_path;
}

////

var encryptDir = function(input_dir, output_dir, encryption_key, crypto_index, options, done) {
  if (typeof options == 'function') {
    done = options;
    options = {};
  }

  console.log('Scanning files...');
  scanDir(input_dir, options, function(err, files, dirs) {
    if (err) {
      console.log(err);
      return done(err);
    }

    if (options.encrypt_files_map && typeof options.encrypt_files_map == 'object') {
      var scanned_files_map = {};
      files.forEach(function(file) {
        scanned_files_map[file.path] = file;
      });
      for (var file_path in options.encrypt_files_map) {
        var orig_file_path = path.join(input_dir, file_path);
        if (!scanned_files_map[orig_file_path]) {
          var file_info = options.encrypt_files_map[file_path];
          files.unshift({
            path: orig_file_path,
            name: file_info['name'],
            // type: file_info['type'],
            size: file_info['size'],
            mode: file_info['mode'],
            atime: file_info['atime'], // last file access
            mtime: file_info['mtime'], // last file modification
            ctime: file_info['ctime'], // last status change time
          });
        }
      }
    }

    if (options.encrypt_entries) {
      files = files.filter(function(file) {
        return options.encrypt_entries.some(function(entry) {
          return (file.path.indexOf(entry) == 0);
        });
      });
    }

    console.log(chalk.blue('Files:'), files.length);

    var crypto_index_version = crypto_index.version();

    if (crypto_index_version != '0.0.1') {
      files = files.filter(function(file) {
        var file_key = utils.md5Hash(path.relative(input_dir, file.path));
        // var file_key = _encryptString(path.relative(input_dir, file.path), encryption_key);
        return !crypto_index.hasKey(file_key);
      });
      var totalSize = 0;
      files.forEach(function(file) {
        totalSize += file.size || 0;
      });
      console.log(chalk.blue('New files:'), files.length, chalk.magenta('('+bytes(totalSize)+')'));
    }
    
    var errors = [];
    var processed = [];
    var encrypted = [];

    var total_size = 0;
    var encrypted_size = 0;

    var total = files.length;
    var count = 0;

    var onFileEncrypt = function(original_file, encrypted_file) {
      if (typeof options.onFileEncrypt == 'function') {
        options.onFileEncrypt(original_file, encrypted_file, {current: count, total: total});
      }
    }

    var onFileEncrypted = function(original_file, encrypted_file) {
      if (typeof options.onFileEncrypted == 'function') {
        options.onFileEncrypted(original_file, encrypted_file, {current: count, total: total});
      }
    }

    var onFileEncryptFailed = function(err, original_file, encrypted_file) {
      console.log(chalk.red('Encrypt file failed:'), original_file.path, err.message);
      if (typeof options.onFileEncryptFailed == 'function') {
        options.onFileEncryptFailed(err, original_file, encrypted_file, {current: count, total: total});
      }
    }

    options.obfuscate = crypto_index.obfuscate();

    console.log('Obfuscate:', options.obfuscate);

    if (files.length) console.log('Encrypting files...');
    async.eachSeries(files, function(file, cb) {
      count++;

      var orig_file_path = path.resolve(file.path);
      var orig_file_rel_path = path.relative(input_dir, orig_file_path);
      
      if (options.progress) console.log(chalk.blue('File:'), count + '/' + total, 
        orig_file_rel_path, chalk.magenta(bytes(file.size)));

      total_size += file.size;

      var encrypted_file_rel_path = getFileHashedPath(orig_file_rel_path, encryption_key, { 
        keep_structure: options.keep_structure 
      });
      var encrypted_file_path = path.join(output_dir, encrypted_file_rel_path);

      if (utils.fileExists(encrypted_file_path)) {
        if (options.verbose) {
          console.log(chalk.yellow('File exists:'), encrypted_file_rel_path);
        }
        if (!crypto_index.get(utils.md5Hash(orig_file_rel_path))) {
          crypto_index.put(utils.md5Hash(orig_file_rel_path), {
            p: orig_file_rel_path,         // path
            ep: encrypted_file_rel_path,   // encrypted file path (relative)
            et: new Date(),                // encrypted time
            s: file.size,                  // size
            m: file.mode,                  // mode
            at: file.atime,                // atime
            mt: file.mtime,                // mtime
            ct: file.ctime,                // ctime
            bt: file.birthtime,            // birthtime
          });
        }
        return cb();
      } else if (!utils.fileExists(orig_file_path)) {
        console.log(chalk.yellow('File missing:'), orig_file_rel_path);
        return cb();
      }

      fse.ensureDirSync(path.dirname(encrypted_file_path));

      onFileEncrypt(file, encrypted_file_rel_path);

      _encryptFile(orig_file_path, encrypted_file_path, encryption_key, options, function(err) {
        if (err) {
          onFileEncryptFailed(err, file, encrypted_file_rel_path);
          errors.push({
            file: file.path,
            error: err.message
          });
          if (options.ignore_errors) {
            if (options.verbose) console.log(err);
            return cb();
          }
          return cb(err);
        }

        onFileEncrypted(file, encrypted_file_rel_path);

        encrypted_size += file.size;
        encrypted.push({
          orig_file: orig_file_rel_path, 
          enc_file: encrypted_file_rel_path
        });

        if (crypto_index_version == '0.0.1') {
          crypto_index.put(encrypted_file_rel_path, {
            path: orig_file_rel_path,
            size: file.size,
            mode: file.mode,
            atime: file.atime,
            mtime: file.mtime,
            ctime: file.ctime,
            birthtime: file.birthtime
          });
        } else {
          crypto_index.put(utils.md5Hash(orig_file_rel_path), {
          // crypto_index.put(_encryptString(file_rel_path, encryption_key), {    
            p: orig_file_rel_path,         // path
            ep: encrypted_file_rel_path,   // encrypted file path (relative)
            et: new Date(),                // encrypted time
            s: file.size,                  // size
            m: file.mode,                  // mode
            at: file.atime,                // atime
            mt: file.mtime,                // mtime
            ct: file.ctime,                // ctime
            bt: file.birthtime,            // birthtime
          });
        }

        if (options.remove_source_files && utils.fileExists(orig_file_path)) {
          fse.removeSync(orig_file_path);
        }

        processed.push(file.path);
        cb();
      });
    }, function(err) {
      if (err) {
        console.log(chalk.red('Encrypting files... Error!'));
        console.log(err);
      }
      if (options.progress) console.log('Encrypting files... OK');

      return done(err, {
        dirs: dirs, 
        files: files, 
        total_size: total_size,
        new_files: encrypted.length,
        processed: processed,
        encrypted: encrypted,
        encrypted_size: encrypted_size,
        errors: errors
      });
    });
  });
}

var decryptDir = function(input_dir, output_dir, encryption_key, crypto_index, options, done) {
  if (typeof options == 'function') {
    done = options;
    options = {};
  }

  if (!options.output_dir) options.output_dir = output_dir;

  var files = [];
  if (crypto_index.version() == '0.0.1') {
    for (var file_hashed_path in crypto_index.map()) {
      files.push({
        encrypted: file_hashed_path, 
        original: crypto_index.get(file_hashed_path)
      });
    }
  } else {
    for (var key in crypto_index.map()) {
      var file_info = crypto_index.get(key);

      var will_decrypt = true;
      if (options.decrypt_entries) {
        will_decrypt = options.decrypt_entries.some(function(entry) {
          return (file_info.p.indexOf(entry) == 0);
        });
      }

      if (will_decrypt) {
        files.push({
          encrypted: file_info.ep, 
          original: {
            path: file_info.p,
            size: file_info.s,
            mode: file_info.m,
            atime: file_info.at,
            mtime: file_info.mt,
            ctime: file_info.ct,
            birthtime: file_info.bt
          }
        });
      }
    }
  }
  
  console.log(chalk.blue('Files:'), files.length);

  var errors = [];
  var processed = [];
  var decrypted = [];

  var total_size = 0;
  var decrypted_size = 0;

  var total = files.length;
  var count = 0;

  var onFileDecrypt = function(decrypted_file, encrypted_file) {
    if (typeof options.onFileDecrypt == 'function') {
      options.onFileDecrypt(decrypted_file, encrypted_file, {current: count, total: total});
    }
  }

  var onFileDecrypted = function(decrypted_file, encrypted_file) {
    if (typeof options.onFileDecrypted == 'function') {
      options.onFileDecrypted(decrypted_file, encrypted_file, {current: count, total: total});
    }
  }

  var onFileDecryptFailed = function(err, decrypted_file, encrypted_file) {
    if (typeof options.onFileDecryptFailed == 'function') {
      options.onFileDecryptFailed(err, decrypted_file, encrypted_file, {current: count, total: total});
    }
  }

  options.obfuscate = crypto_index.obfuscate();
  console.log('Obfuscate:', options.obfuscate);

  console.log('Decrypting files...');
  async.eachSeries(files, function(file, cb) {
    count++;

    if (options.progress) console.log(chalk.blue('File:'), count + '/' + total, 
      orig_file.name, chalk.magenta(bytes(orig_file.size)));

    var orig_file = file.original;
    var encrypted_file = file.encrypted;

    var orig_file_path = path.join(output_dir, orig_file.path);
    var encrypted_file_path = path.join(input_dir, file.encrypted);
    
    total_size += orig_file.size;

    if (!utils.fileExists(encrypted_file_path)) {
      console.log(chalk.yellow('File not found:'), encrypted_file);
      return cb();
    }

    if (utils.fileExists(orig_file_path)) {
      if (options.verbose) {
        console.log(chalk.yellow('File exists:'), orig_file.path);
      }
      return cb();
    }

    fse.ensureDirSync(path.dirname(orig_file_path));

    _decryptFile(encrypted_file_path, orig_file_path, encryption_key, options, function(err) {
      if (err) {
        onFileDecryptFailed(err, orig_file, encrypted_file);
        errors.push({
          file: encrypted_file,
          error: err.message
        });
        if (options.ignore_errors) {
          if (options.verbose) console.log(err);
          return cb();
        }
        return cb(err);
      }

      if (orig_file.atime && orig_file.mtime) {
        var orig_file_atime =  Math.floor((new Date(orig_file.atime)).getTime()/1000);
        var orig_file_mtime =  Math.floor((new Date(orig_file.mtime)).getTime()/1000);
        
        try {
          fs.utimesSync(orig_file_path, orig_file_atime, orig_file_mtime);
        } catch(e) {
          console.log(e);
        }
      }

      onFileDecrypted(orig_file, encrypted_file);

      decrypted_size += orig_file.size;
      decrypted.push({
        enc_file: path.relative(input_dir, encrypted_file), 
        orig_file: orig_file.path
      });

      processed.push(file.encrypted);
      cb();
    });
  }, function(err) {
    if (err) {
      console.log(chalk.red('Decrypting files... Error!'));
      console.log(err);
    }  
    if (options.progress) console.log('Decrypting files... OK');
    
    return done(err, {
      files: files,
      total_size: total_size,
      processed: processed,
      decrypted: decrypted,
      decrypted_size: decrypted_size,
      errors: errors,
    });
  });
}

exports.encryptDir = encryptDir;
exports.decryptDir = decryptDir;

////

var getFileStats = function(file_path) {
  var stats = undefined;
  try {
    stats = fs.lstatSync(file_path);
  } catch(e) {
    console.log(e);
  }
  return stats;
}

var scanDir = function(dir_path, options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }

  if (options.verbose) console.log(chalk.magenta('Directory:'), utils.ellipsisMiddle(dir_path));

  var dirlist = [];
  var filelist = [];

  dirlist.push(dir_path);

  fs.readdir(dir_path, function(err, files) {
    if (err) return callback(err);

    async.eachSeries(files, function(file, cb) {
      
      // if (file.indexOf('.') == 0) { // exclude hidden folders
      //   return cb();
      // }

      var file_path = path.join(dir_path, file);

      var stats = getFileStats(file_path);
      if (!stats) {
        console.log(chalk.yellow('Cannot get stats!') + ' ' + file);
        return cb();
      }

      // console.log(file);
      // console.log(stats);
      
      if (stats.isFile()) {
          if (options.exclude_files && utils.containText(file, options.exclude_files)) {
            return cb();
          }

          var file_size = stats['size'];
          if (options.min_file_size && file_size < options.min_file_size) return cb();
          if (options.max_file_size && file_size > options.max_file_size) return cb();
          
          // var file_type = path.extname(file).replace('.','');
          
          var file_info = {
            path: file_path,
            name: file,
            // type: file_type,
            size: stats['size'],
            mode: stats['mode'],
            atime: stats['atime'], // last file access
            mtime: stats['mtime'], // last file modification
            ctime: stats['ctime'], // last status change time
          };

          if (stats['birthtime']) file_info['birthtime'] = stats['birthtime'];

          filelist.push(file_info);

          cb();
      } else if (stats.isDirectory() && options.recursive) {

        if (options.exclude_dir && file.indexOf(options.exclude_dir) != -1) {
          return cb();
        }
        if (options.exclude_dirs && utils.containText(file, options.exclude_dirs)) {
          return cb();
        }

        scanDir(file_path, options, function(err, files, dirs) {
          if (err) return cb(err);

          filelist = filelist.concat(files);
          dirlist = dirlist.concat(dirs);

          cb();
        });
      } else {
        cb();
      }
    }, function(err) {
      callback(err, filelist, dirlist);
    });
  });
}

