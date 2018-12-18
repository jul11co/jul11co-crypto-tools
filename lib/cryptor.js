// lib/cryptor.js

var fs = require('fs');
var path = require('path');
var util = require('util');
var crypto = require('crypto');
var stream = require('stream');
var Readable = require('stream').Readable;

var async = require('async');
var fse = require('fs-extra');
var chalk = require('chalk');
var bytes = require('bytes');
var once = require('once');

var utils = require('./utils');

var CryptoIndex = require('./crypto-index');

var VERSION = '0.0.6';

var DEFAULT_ALGORITHM = 'aes192';

var supported_algorithms = {
  'aes128': { key_length: 16, iv_length: 16 },
  'aes192': { key_length: 24, iv_length: 16 },
  'aes256': { key_length: 32, iv_length: 16 },
};

exports.VERSION = VERSION;

exports.getVersion = function() {
  return VERSION;
}

exports.generateEncryptionKey = function(passphrase, salt, options) {
  options = options || {};

  if (options.algorithm && supported_algorithms[options.algorithm]) {
    var key_length = supported_algorithms[options.algorithm].key_length;
    return utils.sha512Hash(passphrase, salt).slice(0, key_length);
  }

  return utils.sha512Hash(passphrase, salt); // 128 chars, key will be password
}

////

exports.CryptoIndex = CryptoIndex;

////

var _createCipher = function(algorithm, key, iv) {
  if (!supported_algorithms[algorithm]) {
    console.log('Not supported algorithm:', algorithm);
    return null;
  }
  var key_length = supported_algorithms[algorithm].key_length;
  if (!iv || key_length !== key.length) {
    // crypto.createCipher(algorithm, password[, options])
    return crypto.createCipher(algorithm, key); // assume that key is password
  } else {
    // crypto.createCipheriv(algorithm, key, iv[, options])
    return crypto.createCipheriv(algorithm, key, iv);
  }
}

var _createDecipher = function(algorithm, key, iv) {
  if (!supported_algorithms[algorithm]) {
    console.log('Not supported algorithm:', algorithm);
    return null;
  }
  var key_length = supported_algorithms[algorithm].key_length;
  if (!iv || key_length !== key.length) {
    // crypto.createDecipher(algorithm, password[, options])
    return crypto.createDecipher(algorithm, key); // assume that key is password
  } else {
    // crypto.createDecipheriv(algorithm, key, iv[, options])
    return crypto.createDecipheriv(algorithm, key, iv);
  }
}

var _getKeyLength = function(algorithm) {
  if (!supported_algorithms[algorithm]) {
    return 0;
  }
  return supported_algorithms[algorithm].key_length;
}

var _generateIv = function(algorithm) {
  if (!supported_algorithms[algorithm]) {
    return null;
  }
  var iv_length = supported_algorithms[algorithm].iv_length;
  return new Buffer(crypto.randomBytes(iv_length/2)).toString('hex').slice(0, iv_length);
}

////

var _encryptString = function(input_string, key, options) {
  options = options || {};

  var key_buf = new Buffer(key);
  var algorithm = options.algorithm || DEFAULT_ALGORITHM;

  if (key.length !== _getKeyLength(algorithm)) { // key is password
    var cipher = _createCipher(algorithm, key_buf);
    if (!cipher) {
      console.log('Create cipher failed!');
      return null;
    }

    var crypted = cipher.update(input_string,'utf8','hex');
    crypted += cipher.final('hex');

    return crypted;
  } else {
    var iv_buf = options.iv || _generateIv(algorithm);

    var cipher = _createCipher(algorithm, key_buf, iv_buf);
    if (!cipher) {
      console.log('Create cipher failed!');
      return null;
    }

    var crypted = cipher.update(input_string,'utf8','hex');
    crypted += cipher.final('hex');
    crypted = iv_buf.toString('hex') + ':' + crypted;

    return crypted;
  }
}

var _decryptString = function(input_string, key, options) {
  options = options || {};
  
  var key_buf = new Buffer(key);
  var algorithm = options.algorithm || DEFAULT_ALGORITHM;

  if (key.length !== _getKeyLength(algorithm)) { // key is password
    var decipher = _createDecipher(algorithm, key_buf);
    if (!decipher) {
      console.log('Create decipher failed!');
      return null;
    }

    var decrypted = decipher.update(input_string,'hex','utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } else {
    var input_string_parts = input_string.split(':');
    var iv_string = input_string_parts[0];
    var encrypted_string = input_string_parts[1];

    var decipher = _createDecipher(algorithm, key_buf, iv_string);
    if (!decipher) {
      console.log('Create decipher failed!');
      return null;
    }
    
    var decrypted = decipher.update(encrypted_string,'hex','utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
}

var _encryptFile = function(input_file, output_file, key, options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }

  callback = once(callback);

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
  var iv_buf = null;
  var iv_added = false;

  var algorithm = options.algorithm || DEFAULT_ALGORITHM;

  if (key.length == _getKeyLength(algorithm)) {
    iv_buf = _generateIv(algorithm);
  }

  var cipher = _createCipher(algorithm, key_buf, iv_buf);
  if (!cipher) {
    return callback(new Error('Create cipher failed!'));
  }

  var input_stream = fs.createReadStream(input_file);
  var output_stream = fs.createWriteStream(output_file);

  input_stream.on('data', function(data) {
    if (!iv_added && iv_buf) {
      var iv_data_buf = Buffer.from(iv_buf, 'binary');
      output_stream.write(iv_data_buf);
      iv_added = true;
    }
    var buf = new Buffer(cipher.update(data), 'binary');
    output_stream.write(buf);
  });

  input_stream.on('error', function(err) {
    console.log('Read file failed: ' + input_file, err.message);
    // console.log(err);
    return callback(err);
  });

  input_stream.on('end', function() {
    try {
      var buf = new Buffer(cipher.final('binary'), 'binary');
      output_stream.write(buf);
      output_stream.end();
      output_stream.on('error', function(err) {
        console.log('Write file failed: ' + output_file, err.message);
        // console.log(err);
        return callback(err);
      });
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

  callback = once(callback);

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

  var algorithm = options.algorithm || DEFAULT_ALGORITHM;
  var key_buf = new Buffer(key);

  var iv_buf = null;
  var iv_exists = false;

  if (key.length == _getKeyLength(algorithm)) {
    iv_exists = true;

    // read initialization vector from file
    var iv_buf = new Buffer(16);
    if (options.fd && options.fd != -1) {
      try {
        fs.readSync(options.fd, iv_buf, 0, 16, 0);
      } catch(e) {
        console.log('Read from file failed: ' + input_file);
        return callback(e);
      }
    } else {
      var fd = fs.openSync(input_file, 'r');
      try {
        fs.readSync(fd, iv_buf, 0, 16, 0);
      } catch(e) {
        console.log('Read from file failed: ' + input_file);
        return callback(e);
      } finally {
        fs.closeSync(fd);
      }
    }
    iv_buf = Buffer.from(iv_buf.toString('hex'), 'hex');
    // console.log('IV:', iv_buf);
  }

  var decipher = _createDecipher(algorithm, key_buf, iv_buf);
  if (!decipher) {
    return callback(new Error('Create decipher failed!'));
  }

  var input_stream = fs.createReadStream(input_file, { start: iv_exists ? 16 : 0 });
  var output_stream = fs.createWriteStream(output_file);

  input_stream.on('data', function(data) {
    var buf = new Buffer(decipher.update(data), 'binary');
    output_stream.write(buf);
  });

  input_stream.on('error', function(err) {
    console.log('Read file failed: ' + input_file, err.message);
    // console.log(err);
    return callback(err);
  });

  input_stream.on('end', function() {
    try {
      var buf = new Buffer(decipher.final('binary'), 'binary');
      output_stream.write(buf);
      output_stream.end();
      output_stream.on('error', function(err) {
        console.log('Write file failed: ' + output_file, err.message);
        // console.log(err);
        return callback(err);
      });
      output_stream.on('close', function() {
        return callback();
      });
    } catch(e) {
      fs.unlink(output_file);
      return callback(e);
    }
  });
}

function debugLogFunc() {
  if (typeof (console) !== 'undefined') {
    console.log.apply(console, arguments);
  }
}

// Decode part of file and return a Buffer
// Work with AES-128, 192, 256 (block size: 16 bytes)
var _decryptFilePart = function(input_file, offset, size, key, options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }

  var debugLog = (options.debug) ? debugLogFunc : function(){};

  debugLog('_decryptFilePart:', 'offset:', offset, 'size:', size);

  callback = once(callback);

  var algorithm = options.algorithm || DEFAULT_ALGORITHM;

  var iv_exists = false;
  if (key.length == _getKeyLength(algorithm)) {
    iv_exists = true;
  }

  var aligned_offset = (Math.floor(offset/16)*16); // make sure offset is a multiple of 16 bytes
  var odd_offset = offset - aligned_offset; // 0 <= odd_offset < 16
  // first 16 bytes (first block) to decrypt will be garbage (in case of offset don't start from 0)
  var data_offset = iv_exists 
    ? ((aligned_offset >= 16) ? (aligned_offset) : 16)               /* skip IV in first block */
    : ((aligned_offset >= 16) ? (aligned_offset - 16) : 0);          /* no IV */
  var orig_size = size;
  var data_size = (size + 16); // first 16 bytes will be truncated

  data_size = (Math.ceil(data_size/16)*16); // make sure data size is a multiple of 16 bytes
  data_size = (data_size < 16) ? 16 : data_size;

  debugLog('_decryptFilePart:', 'aligned_offset:', aligned_offset, 'odd_offset:', odd_offset);
  debugLog('_decryptFilePart:', 'data_offset:', data_offset, 'data_size:', data_size);

  var iv_buf = null;
  var data_buf = new Buffer(data_size);

  if (options.fd && options.fd != -1) {
    try {
      if (iv_exists) {
        iv_buf = new Buffer(16);
        fs.readSync(options.fd, iv_buf, 0, 16, 0);
      }
      // fs.readSync(fd, buffer, offset, length, position)
      fs.readSync(options.fd, data_buf, 0, data_size, data_offset);
    } catch(e) {
      console.log('Read from file failed: ' + input_file);
      return callback(e);
    }
  } else {
    var fd = fs.openSync(input_file, 'r');
    try {
      if (iv_exists) {
        iv_buf = new Buffer(16);
        fs.readSync(fd, iv_buf, 0, 16, 0);
      }
      // fs.readSync(fd, buffer, offset, length, position)
      fs.readSync(fd, data_buf, 0, data_size, data_offset);
    } catch(e) {
      console.log('Read from file failed: ' + input_file);
      return callback(e);
    } finally {
      fs.closeSync(fd)
    }
  }

  if (iv_exists && iv_buf) {
    iv_buf = Buffer.from(iv_buf.toString('hex'), 'hex');
    debugLog('_decryptFilePart:', 'iv_buf.length:', iv_buf.length);
  }

  debugLog('_decryptFilePart:', 'data_buf.length:', data_buf.length);

  var key_buf = new Buffer(key);
  var decipher = _createDecipher(algorithm, key_buf, iv_buf);

  decipher.setAutoPadding(false);

  var dec_chunks = [];

  var dec_buf = new Buffer(decipher.update(data_buf), 'binary');

  debugLog('_decryptFilePart:', 'dec_buf.length:', data_buf.length);

  if (dec_buf.length > 16 && offset >= 16) {
    debugLog('_decryptFilePart:', 'dec_buf.length:', dec_buf.length, 'offset:', offset, 
      '--> slice: 16-' + dec_buf.length);
    dec_buf = dec_buf.slice(16); // truncate first 16 bytes
  }
  
  if (odd_offset > 0) {
    debugLog('_decryptFilePart:', 'dec_buf.length:', dec_buf.length, 'odd_offset:', odd_offset, 
      '--> slice: ' + odd_offset + '-' + dec_buf.length);
    dec_buf = dec_buf.slice(odd_offset);
  }

  if (orig_size < data_size && dec_buf.length > orig_size) {
    debugLog('_decryptFilePart:', 'dec_buf.length:', dec_buf.length, 'orig_size:', orig_size, 
      '--> slice: 0-' + orig_size);
    dec_buf = dec_buf.slice(0, orig_size);
  }

  debugLog('_decryptFilePart:', 'dec_buf.length:', dec_buf.length);
  dec_chunks.push(dec_buf);

  var final_buf = new Buffer(decipher.final('binary'), 'binary');
  debugLog('_decryptFilePart:', 'final_buf.length:', final_buf.length);
  dec_chunks.push(final_buf);

  data_buf = null;

  return callback(null, Buffer.concat(dec_chunks));
}

exports.encryptString = _encryptString;
exports.decryptString = _decryptString;
exports.encryptFile = _encryptFile;
exports.decryptFile = _decryptFile;
exports.decryptFilePart = _decryptFilePart;

////

var dir_hash_map = {};

var getDirHashedPath = function(dir_rel_path) {
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
    }
    result_path_parts.push(dir_hash_map[dir_p]);
  }

  return result_path_parts.join(path_sep);
}

var getFileHashedPath = function(file_rel_path, opts) {
  opts = opts || {};
  // calculate file's hashed path
  var file_hashed_name = utils.md5Hash(file_rel_path);
  var file_hashed_rel_path = '';
  if (opts.keep_structure) {
    var dir_name = path.dirname(file_rel_path);
    if (dir_name == '.') {
      file_hashed_rel_path = path.join('DATA', file_hashed_name);
    } else {
      var dir_hashed_path = getDirHashedPath(dir_name);
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

  var scan_opts = {
    recursive: options.recursive,
    min_file_size: options.min_file_size,
    max_file_size: options.max_file_size,
    exclude_files: options.exclude_files,
    exclude_dir: options.exclude_dir,
    exclude_dirs: options.exclude_dirs,
    verbose: options.verbose
  };

  if (options.encrypt_entries && options.encrypt_entries.length) {
    var include_entries = options.encrypt_entries.map(function(entry) {
      return path.join(input_dir, entry);
    });
    scan_opts.include_files = include_entries;
    scan_opts.include_dirs = include_entries;

    if (options.verbose) {
      console.log('Include directories:');
      include_entries.forEach(function(entry) {
        console.log('  -', entry);
      });
    }
  }

  console.log('Scanning files...');
  scanDir(input_dir, scan_opts, function(err, files, dirs) {
    if (err) {
      // console.log(err);
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
            birthtime: file_info['birthtime']
          });
        }
      }
    }

    // if (options.encrypt_entries && options.encrypt_entries.length) {
    //   files = files.filter(function(file) {
    //     return options.encrypt_entries.some(function(entry) {
    //       return (file.path.indexOf(entry) == 0);
    //     });
    //   });
    // }

    console.log(chalk.blue('Files:'), files.length);

    var getNewFiles = function(cb) {
      var new_files = [];
      async.eachSeries(files, function(file_info, cb2) {
        var file_relpath = path.relative(input_dir, file_info.path);
        crypto_index.getFile(file_relpath, function(err, _file) {
          if (!_file) {
            new_files.push(file_info);
          }
          cb2();
        });
      }, function(err) {
        return cb(err, new_files);
      });
    }

    var errors = [];
    var processed = [];
    var encrypted = [];

    var total_size = 0;
    var new_size = 0;
    var encrypted_size = 0;

    var total = files.length;
    var count = 0;

    var onFileEncrypt = function(original_file, encrypted_file) {};
    var onFileEncrypted = function(original_file, encrypted_file) {};
    var onFileEncryptFailed = function(err, original_file, encrypted_file) {};

    if (typeof options.onFileEncrypt == 'function') {
      onFileEncrypt = function(original_file, encrypted_file) {
        options.onFileEncrypt(original_file, encrypted_file, {
          current: count, total: total,
          total_size: new_size, encrypted_size: encrypted_size
        });
      }
    }

    if (typeof options.onFileEncrypted == 'function') {
      onFileEncrypted = function(original_file, encrypted_file) {
        options.onFileEncrypted(original_file, encrypted_file, {
          current: count, total: total,
          total_size: new_size, encrypted_size: encrypted_size
        });
      }
    }

    if (typeof options.onFileEncryptFailed == 'function') {
      onFileEncryptFailed = function(err, original_file, encrypted_file) {
        // console.log(chalk.red('Encrypt file failed:'), original_file.path, err.message);
        options.onFileEncryptFailed(err, original_file, encrypted_file, {
          current: count, total: total,
          total_size: new_size, encrypted_size: encrypted_size
        });
      }
    }

    options.obfuscate = crypto_index.obfuscate();
    if (options.obfuscate) console.log('Obfuscate:', options.obfuscate);

    console.log('Checking files...');
    getNewFiles(function(err, new_files) {
      if (err) {
        console.log('Checking files... Failed.');
        return callback(err);
      }

      new_files.forEach(function(file) {
        new_size += file.size;
      });

      console.log(chalk.blue('New files:'), new_files.length, chalk.magenta('('+bytes(new_size)+')'));

      total = new_files.length;

      if (new_files.length) console.log('Encrypting files...');
      async.eachSeries(new_files, function(file, cb) {
        count++;

        var orig_file_path = path.resolve(file.path);
        var orig_file_rel_path = path.relative(input_dir, orig_file_path);
        
        // if (options.progress) console.log(chalk.blue('File:'), count + '/' + total, 
        //   orig_file_rel_path, chalk.magenta(bytes(file.size)));

        var encrypted_file_rel_path = getFileHashedPath(orig_file_rel_path, { 
          keep_structure: options.keep_structure 
        });
        var encrypted_file_path = path.join(output_dir, encrypted_file_rel_path);

        var doEncryptFile = function() {

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

            encrypted_size += file.size;
            encrypted.push({
              orig_file: orig_file_rel_path, 
              enc_file: encrypted_file_rel_path
            });

            onFileEncrypted(file, encrypted_file_rel_path);

            crypto_index.putFile(orig_file_rel_path, {
              path: orig_file_rel_path,
              size: file.size,
              mode: file.mode,
              atime: file.atime,
              mtime: file.mtime,
              ctime: file.ctime,
              birthtime: file.birthtime,
              encrypted_path: encrypted_file_rel_path,
              encrypted_time: new Date(),
            }, function(err) {

              if (options.remove_source_files && utils.fileExists(orig_file_path)) {
                fse.removeSync(orig_file_path);
              }

              processed.push(file.path);
              return cb();
            }); // putFile
          }); // _encryptFile
        }

        if (utils.fileExists(encrypted_file_path)) {
          // encrypted file already exists
          if (options.verbose) {
            console.log(chalk.yellow('File exists:'), encrypted_file_rel_path);
          }

          crypto_index.getFile(orig_file_rel_path, function(err, _file) {
            if (!_file) {
              // 1. add missing entry
              return crypto_index.putFile(orig_file_rel_path, {
                path: orig_file_rel_path,                 // path
                size: file.size,                          // size
                mode: file.mode,                          // mode
                atime: file.atime,                        // atime
                mtime: file.mtime,                        // mtime
                ctime: file.ctime,                        // ctime
                birthtime: file.birthtime,                // birthtime
                encrypted_path: encrypted_file_rel_path,  // encrypted file path (relative)
                encrypted_time: new Date(),               // encrypted time
              }, function(err) {
                return cb();
              });
            } else if (_file.size == file.size && _file.mtime == file.mtime) {
              // 2. do not replace existing data
              return cb();
            }

            if (options.verbose) {
              console.log(chalk.yellow('File replace:'), encrypted_file_rel_path);
            }

            // 3. continue
            return doEncryptFile();
          });
        } else if (!utils.fileExists(orig_file_path)) {
          console.log(chalk.yellow('File missing:'), orig_file_rel_path);
          return cb();
        } else {
          return doEncryptFile();
        }
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
          new_files: new_files,
          new_size: new_size,
          processed: processed,
          encrypted: encrypted,
          encrypted_size: encrypted_size,
          errors: errors
        });
      }); // async.eachSeries
    }); // getNewFiles
  }); // scanDir
}

var decryptDir = function(input_dir, output_dir, encryption_key, crypto_index, options, done) {
  if (typeof options == 'function') {
    done = options;
    options = {};
  }

  if (!options.output_dir) options.output_dir = output_dir;

  crypto_index.getFileList(function(err, _files) {
  
    if (options.decrypt_entries) {
      _files = _files.filter(function(file_info) {
        return options.decrypt_entries.some(function(entry) {
          return (file_info.path.indexOf(entry) == 0);
        });
      });
    }

    var files = _files.map(function(file_info) {
      return{
        encrypted: file_info.encrypted_path, 
        original: {
          path: file_info.path,
          size: file_info.size,
          mode: file_info.mode,
          atime: file_info.atime,
          mtime: file_info.mtime,
          ctime: file_info.ctime,
          birthtime: file_info.birthtime
        }
      };
    });

    console.log(chalk.blue('Files:'), files.length);

    var errors = [];
    var processed = [];
    var decrypted = [];

    var total_size = 0;
    var decrypted_size = 0;

    var total = files.length;
    var count = 0;

    var onFileDecrypt = function(decrypted_file, encrypted_file) {};
    var onFileDecrypted = function(decrypted_file, encrypted_file) {};
    var onFileDecryptFailed = function(err, decrypted_file, encrypted_file) {};

    if (typeof options.onFileDecrypt == 'function') {
      onFileDecrypt = function(decrypted_file, encrypted_file) {
        options.onFileDecrypt(decrypted_file, encrypted_file, {
          current: count, total: total,
          total_size: total_size, decrypted_size: decrypted_size
        });
      }
    }

    if (typeof options.onFileDecrypted == 'function') {
      onFileDecrypted = function(decrypted_file, encrypted_file) {
        options.onFileDecrypted(decrypted_file, encrypted_file, {
          current: count, total: total,
          total_size: total_size, decrypted_size: decrypted_size
        });
      }
    }

    if (typeof options.onFileDecryptFailed == 'function') {
      onFileDecryptFailed = function(err, decrypted_file, encrypted_file) {
        options.onFileDecryptFailed(err, decrypted_file, encrypted_file, {
          current: count, total: total,
          total_size: total_size, decrypted_size: decrypted_size
        });
      }
    }

    options.obfuscate = crypto_index.obfuscate();
    if (options.obfuscate) console.log('Obfuscate:', options.obfuscate);

    files.forEach(function(file) {
      total_size += file.original.size;
    });

    console.log('Decrypting files...');
    async.eachSeries(files, function(file, cb) {
      count++;

      var orig_file = file.original;
      var encrypted_file = file.encrypted;

      var orig_file_path = path.join(output_dir, orig_file.path);
      var encrypted_file_path = path.join(input_dir, file.encrypted);
      
      // if (options.progress) console.log(chalk.blue('File:'), count + '/' + total, 
      //   orig_file.name, chalk.magenta(bytes(orig_file.size)));

      if (!utils.fileExists(encrypted_file_path)) {
        console.log(chalk.yellow('File not found:'), encrypted_file);

        if (options.remove_encrypted_files) {
          return crypto_index.removeFile(orig_file.path, function(err) {
            return cb();
          });
        }

        return cb();
      }

      if (utils.fileExists(orig_file_path)) {
        if (options.verbose) {
          console.log(chalk.yellow('File exists:'), orig_file.path);
        }
        return cb();
      }

      onFileDecrypt(orig_file, encrypted_file);

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

        if (options.remove_encrypted_files) {
          if (utils.fileExists(encrypted_file_path)) {
            fse.removeSync(encrypted_file_path);
          }

          return crypto_index.removeFile(orig_file.path, function(err) {
            return cb();
          });
        }

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
    }); // async.eachSeries
  }); // crypto_index.getFileList
}

exports.encryptDir = encryptDir;
exports.decryptDir = decryptDir;

var removeFiles = function(input_dir, file_list, encryption_key, crypto_index, options, done) {
  if (typeof options == 'function') {
    done = options;
    options = {};
  }

  crypto_index.getFileList(function(err, _files) {
  
    _files = _files.filter(function(file_info) {
      return file_list.some(function(entry) {
        return (file_info.path.indexOf(entry) == 0);
      });
    });

    var files = _files.map(function(file_info) {
      return{
        encrypted: file_info.encrypted_path, 
        original: {
          path: file_info.path,
          size: file_info.size,
          mode: file_info.mode,
          atime: file_info.atime,
          mtime: file_info.mtime,
          ctime: file_info.ctime,
          birthtime: file_info.birthtime
        }
      };
    });

    console.log(chalk.blue('Files (will be removed):'), files.length);

    var errors = [];
    var processed = [];
    var removed = [];

    var total_size = 0;
    var removed_size = 0;

    var total = files.length;
    var count = 0;

    var onFileRemove = function(decrypted_file, encrypted_file) {};
    var onFileRemoved = function(decrypted_file, encrypted_file) {};
    var onFileRemoveFailed = function(err, decrypted_file, encrypted_file) {};

    if (typeof options.onFileRemove == 'function') {
      onFileRemove = function(decrypted_file, encrypted_file) {
        options.onFileRemove(decrypted_file, encrypted_file, {
          current: count, total: total,
          total_size: total_size, removed_size: removed_size
        });
      }
    }

    if (typeof options.onFileRemoved == 'function') {
      onFileRemoved = function(decrypted_file, encrypted_file) {
        options.onFileRemoved(decrypted_file, encrypted_file, {
          current: count, total: total,
          total_size: total_size, removed_size: removed_size
        });
      }
    }

    if (typeof options.onFileRemoveFailed == 'function') {
      onFileRemoveFailed = function(err, decrypted_file, encrypted_file) {
        options.onFileRemoveFailed(err, decrypted_file, encrypted_file, {
          current: count, total: total,
          total_size: total_size, removed_size: removed_size
        });
      }
    }

    options.obfuscate = crypto_index.obfuscate();
    if (options.obfuscate) console.log('Obfuscate:', options.obfuscate);

    files.forEach(function(file) {
      total_size += file.original.size;
    });

    console.log('Removing files...');
    async.eachSeries(files, function(file, cb) {
      count++;

      var orig_file = file.original;
      var encrypted_file = file.encrypted;
      var encrypted_file_path = path.join(input_dir, file.encrypted);
      
      // if (options.progress) console.log(chalk.blue('File:'), count + '/' + total, 
      //   orig_file.path, chalk.magenta(bytes(orig_file.size)));

      if (!utils.fileExists(encrypted_file_path)) {
        console.log(chalk.yellow('File not found:'), encrypted_file);

        return crypto_index.removeFile(orig_file.path, function(err) {
          return cb();
        });
      }

      onFileRemove(orig_file, encrypted_file);

      fse.remove(encrypted_file_path, function(err) {
        if (err) {
          onFileRemoveFailed(err, orig_file, encrypted_file);
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

        onFileRemoved(orig_file, encrypted_file);

        removed_size += orig_file.size;
        removed.push({
          enc_file: path.relative(input_dir, encrypted_file), 
          orig_file: orig_file.path
        });

        processed.push(file.encrypted);

        crypto_index.removeFile(orig_file.path, function(err) {
          return cb();
        });
      });
    }, function(err) {
      if (err) {
        console.log(chalk.red('Removing files... Error!'));
        console.log(err);
      }  
      if (options.progress) console.log('Removing files... OK');
      
      return done(err, {
        files: files,
        total_size: total_size,
        processed: processed,
        removed: removed,
        removed_size: removed_size,
        errors: errors,
      });
    }); // async.eachSeries
  }); // encrypt_index.getFileList
}

exports.removeFiles = removeFiles;

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
      
      if (stats.isFile()) {
          if (options.exclude_files && utils.containText(file, options.exclude_files)) {
            return cb();
          }
          if (options.include_files && !utils.containText(file_path, options.include_files)) {
            return cb();
          }

          if (options.verbose) console.log(chalk.gray('File:'), utils.ellipsisMiddle(file));

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

          if (stats['birthtime']) {
            file_info['birthtime'] = stats['birthtime'];
          }

          filelist.push(file_info);

          cb();
      } else if (stats.isDirectory() && options.recursive) {

        if (options.exclude_dir && file.indexOf(options.exclude_dir) != -1) {
          return cb();
        }
        if (options.exclude_dirs && utils.containText(file, options.exclude_dirs)) {
          return cb();
        }
        if (options.include_dirs && !utils.containText(file_path, options.include_dirs)) {
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

