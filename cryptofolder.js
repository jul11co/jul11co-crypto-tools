#!/usr/bin/env node

var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

var async = require('async');
var fse = require('fs-extra');
var chalk = require('chalk');
var bytes = require('bytes');
var prompt = require('prompt');

var log = require('single-line-log').stdout;

var utils = require('./lib/utils');
var cryptor = require('./lib/cryptor');

var VERSION = '0.0.2';

function printUsage() {
  console.log('cryptofolder - version ' + VERSION + ', cryptor - version ' + cryptor.getVersion());
  console.log('');
  console.log('Usage:');
  console.log('       cryptofolder --encrypt,-E [OPTIONS] <input-dir> <encrypted-dir>');
  console.log('       cryptofolder --decrypt,-D [OPTIONS] <encrypted-dir> <output-dir> [entries...]');
  console.log('       cryptofolder --list,-L [OPTIONS] <encrypted-dir>');
  console.log('       cryptofolder --browse,-B [OPTIONS] <encrypted-dir>');
  console.log('       cryptofolder --mount,-M [OPTIONS] <encrypted-dir> <mount-point>');
  console.log('');
  console.log('       cryptofolder --config');
  console.log('       cryptofolder --config --set-passphrase');
  console.log('       cryptofolder --config --set-salt');
  console.log('       cryptofolder --config --clear-encryption-key');
  console.log('       cryptofolder --gen-enc-key');
  console.log('');
  console.log('OPTIONS:');
  console.log('');
  console.log('     --force                   -f');
  console.log('     --verbose                 -v');
  console.log('');
  console.log('     --default                 -d    : use default encryption key (if exists)');
  console.log('     --enc-key=STRING                : custom encryption key');
  console.log('');
  console.log('     --recursive               -r    : scan input directory recursively');
  console.log('     --keep-structure          -k    : keep structure as input dir');
  console.log('     --files-map <FILES-MAP>         : include files in map');
  console.log('');
  console.log('     --obfuscate               -o    : obfuscate file name only (do not encrypt file contents)');
  console.log('');
  console.log('     --remove-source-files           : (ENCRYPT) remove source files');
  console.log('     --remove-encrypted-files        : (DECRYPT) remove encrypted files');
  console.log('');
  console.log('     --min-size=<NUMBER>[GB,MB,KB]   : scan for files with minimum size (default: not set)');
  console.log('     --max-size=<NUMBER>[GB,MB,KB]   : scan for files with maximum size (default: not set)');
  console.log('');
  console.log('     --exclude-dir=<STRING>          : exclude directories contain this string');
  console.log('     --exclude-file=<STRING>         : exclude files contain this string');
  console.log('');
}

if (process.argv.length < 3 || process.argv.indexOf('--help') >= 0) {
  printUsage();
  process.exit();
}

var argv = [];
var options = {};
for (var i = 2; i < process.argv.length; i++) {
  if (process.argv[i] == '--encrypt' || process.argv[i] == '-E') {
    options.encrypt = true;
  } else if (process.argv[i] == '--decrypt' || process.argv[i] == '-D') {
    options.decrypt = true;
  } else if (process.argv[i] == '--list' || process.argv[i] == '-L') {
    options.list = true;
  } else if (process.argv[i] == '--browse' || process.argv[i] == '-B') {
    options.browse = true;
  } else if (process.argv[i] == '--mount' || process.argv[i] == '-M') {
    options.mount = true;
  } else if (process.argv[i] == '--default' || process.argv[i] == '-d') {
    options.default = true;
  } else if (process.argv[i] == '--files-map') {
    options.files_map = process.argv[i+1];
    i++;
  } else if (process.argv[i] == '--ignore-errors') {
    options.ignore_errors = true;
  } else if (process.argv[i] == '--stop-if-errors' || process.argv[i] == '-e') {
    options.ignore_errors = false;
  } else if (process.argv[i] == '--recursive' || process.argv[i] == '-r') {
    options.recursive = true;
  } else if (process.argv[i] == '--keep-structure' || process.argv[i] == '-k') {
    options.keep_structure = true;
  } else if (process.argv[i] == '--force' || process.argv[i] == '-f') {
    options.force = true;
  } else if (process.argv[i] == '--verbose' || process.argv[i] == '-v') {
    options.verbose = true;
  } else if (process.argv[i] == '--obfuscate' || process.argv[i] == '-o') {
    options.obfuscate = true;
  } else if (process.argv[i].indexOf('--exclude-dir=') == 0) {
    var dir = process.argv[i].split('=')[1];
    options.exclude_dirs = options.exclude_dirs || [];
    if (options.exclude_dirs.indexOf(dir) == -1) options.exclude_dirs.push(dir);
  } else if (process.argv[i].indexOf('--exclude-file=') == 0) {
    var file = process.argv[i].split('=')[1];
    options.exclude_files = options.exclude_files || [];
    if (options.exclude_files.indexOf(file) == -1) options.exclude_files.push(file);
  } else if (process.argv[i].indexOf('--') == 0) {
    var arg = process.argv[i];
    if (arg.indexOf("=") > 0) {
      var arg_kv = arg.split('=');
      arg = arg_kv[0];
      arg = arg.replace('--','');
      arg = utils.replaceAll(arg, '-', '_');
      options[arg] = arg_kv[1];
    } else {
      arg = arg.replace('--','');
      arg = utils.replaceAll(arg, '-', '_');
      options[arg] = true;
    }
  } else {
    argv.push(process.argv[i]);
  }
}

if (typeof options.ignore_errors == 'undefined') {
  options.ignore_errors = true;
}

if (options.version) {
  console.log('cryptofolder - version ' + VERSION + ', cryptor - version ' + cryptor.getVersion());
  process.exit();
}

// ---

if (options.min_size) {
  var min_size = utils.parseSize(options.min_size);
  if (isNaN(min_size)) {
    console.log('Invalid min size parameter');
    process.exit();
  }
  options.min_file_size = min_size;
  console.log('Min. file size:', bytes(min_size));
}
if (options.max_size) {
  var max_size = utils.parseSize(options.max_size);
  if (isNaN(max_size)) {
    console.log('Invalid max size parameter');
    process.exit();
  }
  options.max_file_size = max_size;
  console.log('Max. file size:', bytes(max_size));
}

// ---

var config = {};
var config_dir = path.join(utils.getUserHome(), '.jul11co', 'crypto-tools');

fse.ensureDirSync(config_dir);

var config_file = path.join(config_dir, 'config.json');
if (utils.fileExists(config_file)) {
  config = utils.loadFromJsonFile(config_file);
}

var generateEncryptionKey = function(passphrase, salt) {
  return utils.sha512Hash(passphrase, salt || options.salt || config.salt || 'jul11co-crypto-tools');
}

var getPromptPassphrase = function(options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }
  
  prompt.message = '';
  prompt.delimiter = '';
  prompt.start();

  prompt.get([{
    name: 'passphrase',
    message: chalk.magenta('Please enter passphrase:'),
    hidden: true
  }], function (err, result) {
    if (err) {
      prompt.stop();
      return callback(err);
    }
    var passphrase = result.passphrase;

    if (!options.verify) {
      prompt.stop();
      return callback(null, passphrase);
    }

    prompt.get([{
      name: 'passphrase',
      message: chalk.magenta('Please re-enter passphrase:'),
      hidden: true
    }], function (err, result) {
      if (err) {
        prompt.stop();
        return callback(err);
      }

      if (passphrase != result.passphrase) {
        console.log('Passphrases don\'t match!');
        prompt.stop();
        return callback(new Error('Passphrases don\'t match!'));
      }

      prompt.stop();
      return callback(null, passphrase);
    });
  });
}

var getPromptSalt = function(options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }
  
  prompt.message = '';
  prompt.delimiter = '';
  prompt.start();

  prompt.get([{
    name: 'salt',
    message: chalk.magenta('Please enter salt:'),
    hidden: true
  }], function (err, result) {
    if (err) {
      prompt.stop();
      return callback(err);
    }
    
    prompt.stop();
    return callback(null, result.salt);
  });
}

/////

function _encrypt(INPUT_DIR, OUTPUT_DIR, ENC_KEY, options, done) {

  if (OUTPUT_DIR != INPUT_DIR) {
    fse.ensureDirSync(OUTPUT_DIR);
  }

  if (options.files_map && utils.fileExists(options.files_map)) {
    console.log('Files map:', options.files_map);
    options.encrypt_files_map = utils.loadFromJsonFile(options.files_map);
  }

  var crypto_index = new cryptor.CryptoIndex(
    path.join(OUTPUT_DIR, 'INDEX'), 
    ENC_KEY, 
    {
      debug: options.debug,
      obfuscate: options.obfuscate
    }
  );
  crypto_index.load(function(err) {
    if (err) {
      console.log('Load crypto index error!');
      // console.log(err);
      if (err.message.indexOf('bad decrypt')!=-1) {
        console.log(chalk.red('Wrong passphrase.'));
      }
      process.exit();
    }

    options.onFileEncrypt = function(original_file, encrypted_file, progress) {
      log(chalk.magenta('Encrypting:'), progress.current + '/' + progress.total, 
        utils.ellipsisMiddle(path.relative(INPUT_DIR, original_file.path),60), chalk.magenta(bytes(original_file.size)));
    }
    options.onFileEncrypted = function(original_file, encrypted_file, progress) {
      log(chalk.green('Encrypted:'), progress.current + '/' + progress.total, 
        utils.ellipsisMiddle(path.relative(INPUT_DIR, original_file.path),60), chalk.magenta(bytes(original_file.size)));
    }
    options.onFileEncryptFailed = function(err, original_file, encrypted_file, progress) {
      log(chalk.red('Encrypt failed:'), progress.current + '/' + progress.total, 
        utils.ellipsisMiddle(original_file.path,60), chalk.magenta(bytes(original_file.size)), err.message);
    }

    process.on('SIGINT', function() {
      console.log("\nCaught interrupt signal");
      crypto_index.unload(function(err) {
        if (err) {
          console.log('Unload crypto index error!');
          console.log(err);
        }
        process.exit();
      });
    });

    cryptor.encryptDir(INPUT_DIR, OUTPUT_DIR, ENC_KEY, crypto_index, options, function(err, result) {
      if (err) {
        console.log('Encrypt folder error!');
        console.log(err);
      } else if (result) {
        console.log('----');
        console.log('Directory:', result.dirs.length);
        console.log('Total:', result.files.length + ' file' + ((result.files.length != 1) ? 's.': '.'));

        // console.log('Processed:', result.processed.length + ' file' + ((result.processed.length != 1) ? 's': '') 
        //   + ' (' + bytes(result.total_size) + ').');

        if (result.encrypted && result.encrypted.length) {
          console.log('Encrypted:', result.encrypted.length 
            + ' file' + ((result.encrypted.length != 1) ? 's': '') 
            + ' (' + bytes(result.encrypted_size) + ').');
        }
        
        if (result.errors && result.errors.length) {
          console.log('----');
          console.log(chalk.red(errors.length + ' errors.'));
          result.errors.forEach(function(error) {
            console.log(error);
          });
        }
      }
      crypto_index.unload(function(err) {
        if (err) {
          console.log('Unload crypto index error!');
          console.log(err);
        }
        process.exit();
      })
    });
  });
}

function _decrypt(INPUT_DIR, OUTPUT_DIR, ENC_KEY, options, done) {

  if (OUTPUT_DIR != INPUT_DIR) {
    fse.ensureDirSync(OUTPUT_DIR);
  }

  var crypto_index = new cryptor.CryptoIndex(
    path.join(INPUT_DIR, 'INDEX'), 
    ENC_KEY, 
    {
      read_only: true, 
      debug: options.debug
    }
  );
  crypto_index.load(function(err) {
    if (err) {
      console.log('Load crypto index error!');
      // console.log(err);
      if (err.message.indexOf('bad decrypt')!=-1) {
        console.log(chalk.red('Wrong passphrase.'));
      }
      process.exit();
    }

    options.onFileDecrypt = function(decrypted_file, encrypted_file, progress) {
      log(chalk.magenta('Decrypting:'), progress.current + '/' + progress.total, 
        utils.ellipsisMiddle(decrypted_file.path,60), chalk.magenta(bytes(decrypted_file.size)));
    }
    options.onFileDecrypted = function(decrypted_file, encrypted_file, progress) {
      log(chalk.green('Decrypted:'), progress.current + '/' + progress.total, 
        utils.ellipsisMiddle(decrypted_file.path,60), chalk.magenta(bytes(decrypted_file.size)));
    }
    options.onFileDecryptFailed = function(err, decrypted_file, encrypted_file, progress) {
      log(chalk.red('Decrypted failed:'), progress.current + '/' + progress.total, 
        utils.ellipsisMiddle(decrypted_file.path,60), chalk.magenta(bytes(decrypted_file.size)));
    }

    cryptor.decryptDir(INPUT_DIR, OUTPUT_DIR, ENC_KEY, crypto_index, options, function(err, result) {
      if (err) {
        console.log('Decrypt folder error!');
        console.log(err);
      } else if (result) {
        console.log('----');
        console.log('Total:', result.files.length + ' file' + ((result.files.length != 1) ? 's.': '.'));

        // console.log('Processed:', result.processed.length + ' file' + ((result.processed.length != 1) ? 's': '') 
        //   + ' (' + bytes(result.total_size) + ') processed.');

        if (result.decrypted && result.decrypted.length) {
          console.log('Decrypted:', result.decrypted.length 
            + ' file' + ((result.decrypted.length != 1) ? 's': '') 
            + ' (' + bytes(result.decrypted_size) + ').');
        }

        if (result.errors && result.errors.length) {
          console.log('----');
          console.log(chalk.red(result.errors.length + ' errors.'));
          result.errors.forEach(function(error) {
            console.log(error);
          });
        }
      }
      crypto_index.unload(function(err) {
        if (err) {
          console.log('Unload crypto index error!');
          console.log(err);
        }
        process.exit();
      });
    });
  });
}

function _list(INPUT_DIR, ENC_KEY, options, done) {

  var crypto_index = new cryptor.CryptoIndex(
    path.join(INPUT_DIR, 'INDEX'), 
    ENC_KEY, 
    {
      read_only: true, 
      debug: options.debug
    }
  );
  crypto_index.load(function(err) {
    if (err) {
      console.log('Load crypto index error!');
      // console.log(err);
      if (err.message.indexOf('bad decrypt')!=-1) {
        console.log(chalk.red('Wrong passphrase.'));
      }
      process.exit();
    }

    var count = 0;
    var total_size = 0;
    var largest_size = 0;
    var largest_file = {};

    // print file list from INDEX
    for (var file_id in crypto_index.map()) {
      var file_info = crypto_index.get(file_id);
      var will_list = true;
      if (options.list_entries) {
        will_list = options.list_entries.some(function(entry) {
          return (file_info.p.indexOf(entry) == 0);
        });
      }
      if (will_list) {
        count++;
        console.log(utils.padLeft(''+count, 6)+'.', 
          chalk.magenta(utils.padLeft(bytes(file_info.s), 8)), file_info.p);
        total_size += file_info.s;
        if (file_info.s > largest_size) {
          largest_size = file_info.s;
          largest_file = {path: file_info.p, size: file_info.s};
        }
      }
    }

    console.log('----');
    console.log('Total files:', count);
    console.log('Total size:', bytes(total_size));
    if (largest_size>0) {
      console.log('Largest file:', chalk.magenta(bytes(largest_file.size)), largest_file.path);
    }

    crypto_index.unload(function(err) {
      if (err) {
        console.log('Unload crypto index error!');
        console.log(err);
      }
      process.exit();
    });
  });
}

function _browse(INPUT_DIR, ENC_KEY, options, done) {

  // temp dir
  var TMP_DIR = path.join(config_dir, 'caches', utils.md5Hash(INPUT_DIR));
  var DECRYPTED_TMP_DIR = path.join(TMP_DIR, '_DECRYPTED');

  var crypto_index = null;
  var entries_map = {};

  process.on('exit', function() {
    fse.emptyDirSync(DECRYPTED_TMP_DIR);
    fse.emptyDirSync(TMP_DIR);
  });

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

  var loadCryptoIndex = function(callback) {
    if (!crypto_index) return callback(new Error('Crypto index not specified.'));
    if (crypto_index.loaded()) return callback();
    // load index
    crypto_index.load(function(err) {
      if (err) {
        console.log('Load crypto index error!');
        // console.log(err);
        if (err.message.indexOf('bad decrypt')!=-1) {
          console.log(chalk.red('Wrong passphrase.'));
        }
        return callback(err);
      }
      callback();
    });
  }

  var unloadCryptoIndex = function(callback) {
    if (!crypto_index || !crypto_index.loaded()) return callback();
    crypto_index.unload(function(err) {
      if (err) {
        console.log('Unload crypto index error!');
        console.log(err);
      }
      callback(err);
    });
  }

  var listFolder = function(opts, callback) {
    if (typeof opts == 'function') {
      callback = opts;
      opts = {};
    }
    if (!crypto_index.loaded()) {
      return loadCryptoIndex(function(err) {
        if (err) {
          return callback(err);
        }
        listFolder(opts, callback);
      });
    }

    var result = {
      entries: [],
      totalSize: 0
    }

    for (var file_id in crypto_index.map()) {
      var file_info = crypto_index.get(file_id);
      var entry = {
        type: 'file',
        path: file_info.p,
        size: file_info.s,
        mode: file_info.m,
        atime: file_info.at,
        mtime: file_info.mt,
        ctime: file_info.ct,
        birthtime: file_info.bt,
        encrypted_path: file_info.ep,
        encrypted_time: file_info.et
      };
      entries_map[entry.path] = entry;
      // add entries for parent dirs (if not added)
      var dirs = getParentDirs(entry.path);
      if (dirs.length) {
        dirs.forEach(function(dir_relpath) {
          if (!entries_map[dir_relpath]) {
            entries_map[dir_relpath] = {
              type: 'directory',
              path: dir_relpath,
              size: 0,
              mtime: entry.mtime
            }
          } else if (entries_map[dir_relpath].mtime < entry.ctime) {
            entries_map[dir_relpath].mtime = entry.ctime;
          }
        });
      }
    }

    for (var entry_path in entries_map) {
      var entry = entries_map[entry_path];
      result.totalSize += entry.size;
      result.entries.push(entry);
    }

    unloadCryptoIndex(function() {
      return callback(null, result);
    });
  }

  var getEntry = function(fpath, output_dir, opts, callback) {
    if (!entries_map[fpath] || !entries_map[fpath].encrypted_path) {
      return callback(new Error('Entry not found: ' + fpath));
    }
    
    var entry = entries_map[fpath];
    var encrypted_file_abs_path = path.join(INPUT_DIR, entry.encrypted_path);

    console.log('getEntry:', bytes(entry.size), fpath);

    var decrypted_file_abs_path = path.join(output_dir, entry.path);
    fse.ensureDirSync(path.dirname(decrypted_file_abs_path));

    var decrypt_opts = {
      obfuscate: crypto_index.obfuscate()
    };

    cryptor.decryptFile(encrypted_file_abs_path, decrypted_file_abs_path, ENC_KEY, decrypt_opts, function(err) {
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
  }

  // fse.ensureDirSync(TMP_DIR);
  fse.emptyDirSync(TMP_DIR);

  console.log('Loading cryptofolder...');
  crypto_index = new cryptor.CryptoIndex(
    path.join(INPUT_DIR, 'INDEX'), 
    ENC_KEY, 
    {
      read_only: true,
      debug: options.debug
    });

  var crypto_source = {
    path: INPUT_DIR,
    listEntry: listFolder,
    getEntry: getEntry,
  };

  require('./lib/crypto-browser')(crypto_source, DECRYPTED_TMP_DIR, options);
}

function _mount(INPUT_DIR, MOUNT_POINT, ENC_KEY, options, done) {

  // temp dir
  var TMP_DIR = path.join(config_dir, 'caches', utils.md5Hash(INPUT_DIR));

  var DECRYPTED_TMP_DIR = path.join(TMP_DIR, '_DECRYPTED');
  options.tmp_dir = DECRYPTED_TMP_DIR;

  var crypto_index = null;
  var entries_map = {};

  process.on('exit', function() {
    fse.emptyDirSync(DECRYPTED_TMP_DIR);
    fse.emptyDirSync(TMP_DIR);
  });

  var loadCryptoIndex = function(callback) {
    if (!crypto_index) return callback(new Error('Crypto index not specified.'));
    if (crypto_index.loaded()) return callback();
    // load index
    crypto_index.load(function(err) {
      if (err) {
        console.log('Load crypto index error!');
        // console.log(err);
        if (err.message.indexOf('bad decrypt')!=-1) {
          console.log(chalk.red('Wrong passphrase.'));
        }
        return callback(err);
      }
      callback();
    });
  }

  var unloadCryptoIndex = function(callback) {
    if (!crypto_index || !crypto_index.loaded()) return callback();
    crypto_index.unload(function(err) {
      if (err) {
        console.log('Unload crypto index error!');
        console.log(err);
      }
      callback(err);
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

  var listFolder = function(opts, callback) {
    if (typeof opts == 'function') {
      callback = opts;
      opts = {};
    }
    if (!crypto_index.loaded()) {
      return loadCryptoIndex(function(err) {
        if (err) {
          return callback(err);
        }
        listFolder(opts, callback);
      });
    }

    var result = {
      entries: [],
      totalSize: 0
    }

    for (var file_id in crypto_index.map()) {
      var file_info = crypto_index.get(file_id);
      var entry = {
        type: 'file',
        path: file_info.p,
        size: file_info.s,
        mode: file_info.m,
        atime: file_info.at,
        mtime: file_info.mt,
        ctime: file_info.ct,
        birthtime: file_info.bt,
        encrypted_path: file_info.ep,
        encrypted_time: file_info.et
      };
      entries_map[entry.path] = entry;
      // add entries for parent dirs (if not added)
      var dirs = getParentDirs(entry.path);
      if (dirs.length) {
        dirs.forEach(function(dir_relpath) {
          if (!entries_map[dir_relpath]) {
            entries_map[dir_relpath] = {
              type: 'directory',
              path: dir_relpath,
              size: 0,
              mtime: entry.mtime
            }
          } else if (entries_map[dir_relpath].mtime < entry.ctime) {
            entries_map[dir_relpath].mtime = entry.ctime;
          }
        });
      }
    }

    for (var entry_path in entries_map) {
      var entry = entries_map[entry_path];
      result.totalSize += entry.size;
      result.entries.push(entry);
    }

    unloadCryptoIndex(function() {
      return callback(null, result);
    });
  }

  var getEntry = function(fpath, output_dir, opts, callback) {
    if (!entries_map[fpath] || !entries_map[fpath].encrypted_path) {
      return callback(new Error('Entry not found: ' + fpath));
    }
    
    var entry = entries_map[fpath];
    var encrypted_file_abs_path = path.join(INPUT_DIR, entry.encrypted_path);

    // console.log('extractEntry:', fpath);

    var decrypted_file_abs_path = path.join(output_dir, entry.path);
    fse.ensureDirSync(path.dirname(decrypted_file_abs_path));

    var decrypt_opts = {
      obfuscate: crypto_index.obfuscate()
    };

    cryptor.decryptFile(encrypted_file_abs_path, decrypted_file_abs_path, ENC_KEY, decrypt_opts, function(err) {
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
  }

  // fse.ensureDirSync(TMP_DIR);
  fse.emptyDirSync(TMP_DIR);

  console.log('Loading cryptofolder...');
  crypto_index = new cryptor.CryptoIndex(
    path.join(INPUT_DIR, 'INDEX'), 
    ENC_KEY, 
    {
      read_only: true,
      debug: options.debug
    });

  if (!utils.directoryExists(MOUNT_POINT)) {
    fse.ensureDirSync(MOUNT_POINT);
  }

  var mounted = false;
  var crypto_mount = require('./lib/crypto-mount');

  var crypto_source = {
    path: INPUT_DIR,
    list: listFolder,
    getEntry: getEntry
  };
  crypto_mount.mount(crypto_source, MOUNT_POINT, DECRYPTED_TMP_DIR, options, function(err) {
    if (err) {
      console.log(err);
      return done(err);
    } else {
      mounted = true;
      console.log('Crypto folder mounted on ' + MOUNT_POINT);

      process.on('SIGINT', function () {
        if (!mounted) return;

        crypto_mount.unmount(crypto_source, MOUNT_POINT,function(err) {
          if (err) {
            console.log('Can not unmount: ' + MOUNT_POINT, err);
            console.log(err);
          } else {
            console.log('Unmounted: ' + MOUNT_POINT);
          }
        });
      })
    }
  });
}

/////

if (options.config) {
  if (options.set_passphrase) {
    getPromptPassphrase({verify: true}, function(err, passphrase) {
      if (err) {
        // console.log(err);
        console.log('');
        process.exit();
      }
      var enc_key = generateEncryptionKey(passphrase);
      config.enc_key = enc_key;
      utils.saveToJsonFile(config, config_file);
      console.log('Config saved.');
      process.exit();
    });
  } else if (options.clear_encryption_key) {
    delete config.enc_key;    
    utils.saveToJsonFile(config, config_file);
    console.log('Config saved.');
    process.exit();
  }else if (options.set_salt) {
    getPromptSalt(function(err, salt) {
      if (err) {
        // console.log(err);
        console.log('');
        process.exit();
      }
      config.salt = salt;
      utils.saveToJsonFile(config, config_file);
      console.log('Config saved.');
      process.exit();
    });
  } else {
    console.log(config);
    process.exit();
  }
} else if (options.gen_enc_key) {
  getPromptPassphrase({verify: true}, function(err, passphrase) {
    if (err) {
      // console.log(err);
      process.exit();
    }
    var ENC_KEY = generateEncryptionKey(passphrase);
    console.log('Encryption key:', ENC_KEY);
  });
} else if (options.encrypt) {

  if (argv.length < 2) {
    printUsage();
    process.exit();
  }

  var INPUT_DIR = path.resolve(argv[0]);
  if (!utils.directoryExists(INPUT_DIR)) {
    console.log(chalk.red('Directory not found:'), INPUT_DIR);
    process.exit();
  }
  console.log('Input dir: ' + INPUT_DIR);
  options.input_dir = INPUT_DIR;

  var OUTPUT_DIR = path.resolve(argv[1]);
  if (!options.force && utils.directoryExists(OUTPUT_DIR)) {
    console.log(chalk.yellow('Directory exists:'), OUTPUT_DIR);
    console.log(chalk.grey('Hint: Add --force or -f to merge/replace files in existing directory.'));
    process.exit();
  }
  console.log('Output dir: ' + OUTPUT_DIR);
  options.output_dir = OUTPUT_DIR;
  
  var entries_to_encrypt = [];
  if (argv.length > 2) {
    for (var i = 2; i < argv.length; i++) {
      entries_to_encrypt.push(argv[i]);
    }
  }
  if (entries_to_encrypt.length) {
    options.encrypt_entries = entries_to_encrypt;
  }

  if ((options.default && config.enc_key) || options.enc_key) {
    _encrypt(INPUT_DIR, OUTPUT_DIR, options.enc_key || config.enc_key, options, function(err) {
      if (err) {
        console.log(err);
      }
      process.exit();
    })
  } else {
    getPromptPassphrase({verify: true}, function(err, passphrase) {
      if (err) {
        // console.log(err);
        console.log('');
        process.exit();
      }
      var ENC_KEY = generateEncryptionKey(passphrase);
      _encrypt(INPUT_DIR, OUTPUT_DIR, ENC_KEY, options, function(err) {
        if (err) {
          console.log(err);
        }
        process.exit();
      })
    });
  }
} else if (options.decrypt) {

  if (argv.length < 2) {
    printUsage();
    process.exit();
  }

  var INPUT_DIR = path.resolve(argv[0]);
  if (!utils.directoryExists(INPUT_DIR)) {
    console.log(chalk.red('Directory not found:'), INPUT_DIR);
    process.exit();
  }
  console.log('Input directory: ' + INPUT_DIR);
  options.input_dir = INPUT_DIR;

  var OUTPUT_DIR = path.resolve(argv[1]);
  if (!options.force && utils.directoryExists(OUTPUT_DIR)) {
    console.log(chalk.yellow('Directory exists:'), OUTPUT_DIR);
    console.log(chalk.grey('Hint: Add --force or -f to merge/replace files in existing directory.'));
    process.exit();
  }
  console.log('Output dir: ' + OUTPUT_DIR);
  options.output_dir = OUTPUT_DIR;

  var entries_to_decrypt = [];
  if (argv.length > 2) {
    for (var i = 2; i < argv.length; i++) {
      entries_to_decrypt.push(argv[i]);
    }
  }
  if (entries_to_decrypt.length) {
    options.decrypt_entries = entries_to_decrypt;
  }

  if ((options.default && config.enc_key) || options.enc_key) {
    _decrypt(INPUT_DIR, OUTPUT_DIR, options.enc_key || config.enc_key, options, function(err) {
      if (err) {
        console.log(err);
      }
      process.exit();
    })
  } else {
    getPromptPassphrase(function(err, passphrase) {
      if (err) {
        // console.log(err);
        console.log('');
        process.exit();
      }
      var ENC_KEY = generateEncryptionKey(passphrase);
      _decrypt(INPUT_DIR, OUTPUT_DIR, ENC_KEY, options, function(err) {
        if (err) {
          console.log(err);
        }
        process.exit();
      })
    });
  }

} else if (options.list) {

  if (argv.length < 1) {
    printUsage();
    process.exit();
  }

  var INPUT_DIR = path.resolve(argv[0]);
  if (!utils.directoryExists(INPUT_DIR)) {
    console.log(chalk.red('Directory not found:'), INPUT_DIR);
    process.exit();
  }
  console.log('Input directory: ' + INPUT_DIR);
  options.input_dir = INPUT_DIR;
  
  var entries_to_list = [];
  if (argv.length > 1) {
    for (var i = 1; i < argv.length; i++) {
      entries_to_list.push(argv[i]);
    }
  }
  if (entries_to_list.length) {
    options.list_entries = entries_to_list;
  }

  if ((options.default && config.enc_key) || options.enc_key) {
    _list(INPUT_DIR, options.enc_key || config.enc_key, options, function(err) {
      if (err) {
        console.log(err);
      }
      process.exit();
    })
  } else {
    getPromptPassphrase(function(err, passphrase) {
      if (err) {
        // console.log(err);
        console.log('');
        process.exit();
      }
      var ENC_KEY = generateEncryptionKey(passphrase);
      _list(INPUT_DIR, ENC_KEY, options, function(err) {
        if (err) {
          console.log(err);
        }
        process.exit();
      })
    });
  }
} else if (options.browse) {

  if (argv.length < 1) {
    printUsage();
    process.exit();
  }

  var INPUT_DIR = path.resolve(argv[0]);
  if (!utils.directoryExists(INPUT_DIR)) {
    console.log(chalk.red('Directory not found:'), INPUT_DIR);
    process.exit();
  }
  console.log('Input directory: ' + INPUT_DIR);
  options.input_dir = INPUT_DIR;
  
  if ((options.default && config.enc_key) || options.enc_key) {
    _browse(INPUT_DIR, options.enc_key || config.enc_key, options, function(err) {
      if (err) {
        console.log(err);
      }
    })
  } else if (options.passphrase) {
    var ENC_KEY = generateEncryptionKey(options.passphrase);
    _browse(INPUT_DIR, ENC_KEY, options, function(err) {
      if (err) {
        console.log(err);
      }
    })
  } else {
    getPromptPassphrase(function(err, passphrase) {
      if (err) {
        // console.log(err);
        console.log('');
        process.exit();
      }
      var ENC_KEY = generateEncryptionKey(passphrase);
      _browse(INPUT_DIR, ENC_KEY, options, function(err) {
        if (err) {
          console.log(err);
        }
      })
    });
  }
} else if (options.mount) {

  if (argv.length < 2) {
    printUsage();
    process.exit();
  }

  var INPUT_DIR = path.resolve(argv[0]);
  if (!utils.directoryExists(INPUT_DIR)) {
    console.log(chalk.red('Directory not found:'), INPUT_DIR);
    process.exit();
  }
  console.log('Input directory: ' + INPUT_DIR);
  options.input_dir = INPUT_DIR;

  var MOUNT_POINT = path.resolve(argv[1]);
  options.mount_point = MOUNT_POINT;
  console.log('Mount point: ' + MOUNT_POINT);
  
  if ((options.default && config.enc_key) || options.enc_key) {
    _mount(INPUT_DIR, MOUNT_POINT, options.enc_key || config.enc_key, options, function(err) {
      if (err) {
        console.log(err);
      }
    })
  } else if (options.passphrase) {
    var ENC_KEY = generateEncryptionKey(options.passphrase);
    _mount(INPUT_DIR, MOUNT_POINT, ENC_KEY, options, function(err) {
      if (err) {
        console.log(err);
      }
    })
  } else {
    getPromptPassphrase(function(err, passphrase) {
      if (err) {
        // console.log(err);
        console.log('');
        process.exit();
      }
      var ENC_KEY = generateEncryptionKey(passphrase);
      _mount(INPUT_DIR, MOUNT_POINT, ENC_KEY, options, function(err) {
        if (err) {
          console.log(err);
        }
      })
    });
  }
} else {
  printUsage();
  process.exit();
}
