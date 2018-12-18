#!/usr/bin/env node

var fs = require('fs');
var path = require('path');

var async = require('async');
var fse = require('fs-extra');
var chalk = require('chalk');
var bytes = require('bytes');
var moment = require('moment');

var log = require('single-line-log').stdout;
// var prettySeconds = require('pretty-seconds');
var prettyMs = require('pretty-ms');

var utils = require('./lib/utils');
var cryptor = require('./lib/cryptor');

var cryptoUtils = require('./lib/crypto-utils');
var CryptoFolder = require('./lib/crypto-folder');

var VERSION = '0.0.3';

function printUsage() {
  console.log('cryptofolder - version ' + VERSION + ', cryptor - version ' + cryptor.getVersion());
  console.log('');
  console.log('Usage:');
  console.log('       cryptofolder encrypt [OPTIONS] <input-dir> <encrypted-dir>');
  console.log('       cryptofolder decrypt [OPTIONS] <encrypted-dir> <output-dir> [entries...]');
  console.log('       cryptofolder remove [OPTIONS] <encrypted-dir> [entries...]');
  console.log('       cryptofolder list [OPTIONS] <encrypted-dir>');
  console.log('       cryptofolder browse [OPTIONS] <encrypted-dir>');
  console.log('       cryptofolder mount [OPTIONS] <encrypted-dir> <mount-point> [--read-write]');
  console.log('');
  console.log('       cryptofolder trash:list [OPTIONS] <encrypted-dir>');
  console.log('       cryptofolder trash:empty [OPTIONS] <encrypted-dir>');
  console.log('');
  console.log('       cryptofolder folder:list');
  console.log('       cryptofolder folder:add <encrypted-dir>');
  console.log('       cryptofolder folder:remove <encrypted-dir>');
  console.log('       cryptofolder folder:move <old-dir> <new-dir>');
  console.log('');
  console.log('       cryptofolder config:show');
  console.log('       cryptofolder config:set-salt');
  console.log('       cryptofolder config:set-encryption-key');
  console.log('       cryptofolder config:clear-encryption-key');
  console.log('');
  console.log('       cryptofolder gen-enc-key');
  console.log('');
  console.log('OPTIONS:');
  console.log('');
  console.log('     --force                   -f');
  console.log('     --verbose                 -v');
  console.log('');
  console.log('     --default                 -d    : use default encryption key (if exists)');
  console.log('     --enc-key=STRING                : use custom encryption key');
  console.log('     --salt=STRING                   : use custom salt');
  console.log('     --save-enc-key                  : (ENCRYPT/DECRYPT) save encryption key to config');
  console.log('');
  console.log('     --algorithm=ALGORITHM           : (ENCRYPT) set encryption algorithm (aes128, aes192, aes256)');
  console.log('');
  console.log('     --recursive               -r    : (ENCRYPT) scan input directory recursively (default: yes)');
  console.log('     --no-recursive            -n    : (ENCRYPT) only scan input directory (not recursively)');
  console.log('     --keep-structure          -k    : (ENCRYPT) keep structure as in input directory');
  console.log('     --files-map <FILES-MAP>         : (ENCRYPT) include files in map');
  console.log('');
  console.log('     --obfuscate               -o    : (ENCRYPT) obfuscate file names only (do not encrypt file contents)');
  console.log('');
  console.log('     --remove-source-files           : (ENCRYPT) remove source files');
  console.log('     --remove-encrypted-files        : (DECRYPT) remove encrypted files');
  console.log('');
  console.log('     --min-size=<NUMBER>[GB,MB,KB]   : (ENCRYPT) scan for files with minimum size (default: not set)');
  console.log('     --max-size=<NUMBER>[GB,MB,KB]   : (ENCRYPT) scan for files with maximum size (default: not set)');
  console.log('');
  console.log('     --exclude-dir=<STRING>          : (ENCRYPT) exclude directories contain this string');
  console.log('     --exclude-file=<STRING>         : (ENCRYPT) exclude files contain this string');
  console.log('');
  console.log('     --no-daemon               -N    : (MOUNT) do not daemonize mount command');
  console.log('     --read-write                    : (MOUNT) mount as writeable mount point');
  console.log('');
}

if (process.argv.length < 3 || process.argv.indexOf('--help') >= 0) {
  printUsage();
  process.exit();
}

var command = process.argv[2];
var argv = [];
var options = {
  recursive: true
};
for (var i = 3; i < process.argv.length; i++) {
  if (process.argv[i] == '--default' || process.argv[i] == '-d') {
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
  } else if (process.argv[i] == '--no-recursive' || process.argv[i] == '-n') {
    options.recursive = false;
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
  } else if (process.argv[i] == '--no-daemon' || process.argv[i] == '-N') {
    options.daemon = false;
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
if (command == 'mount' && typeof options.daemon == 'undefined') {
  options.daemon = true;
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

var crypto_salt = options.salt || config.salt || 'jul11co-crypto-tools';
var crypto_algorithm = options.algorithm || 'aes256';

var loadAlgorithmFromFolder = function(crypto_dir) {
  var algorithm_file = path.join(crypto_dir, 'ALGO');
  if (utils.fileExists(algorithm_file)) {
    try {
      return fs.readFileSync(algorithm_file, {encoding: 'utf8'});
    } catch(e) {
      console.log(e);
      return null;
    }
  }
  if (!utils.fileExists(path.join(crypto_dir, 'INDEX'))) { // new crypto folder ?
    return crypto_algorithm;
  }
  return null;
}

var saveAlgorithmToFolder = function(crypto_dir, algorithm) {
  var algorithm_file = path.join(crypto_dir, 'ALGO');
  fse.ensureDirSync(crypto_dir);
  if (!utils.fileExists(algorithm_file) && algorithm) { // Do not alter existing ALGO file
    fs.writeFileSync(algorithm_file, algorithm, {encoding: 'utf8'});
  }
}

var getEncryptionKey = function(opts, callback) {
  if (typeof opts == 'function') {
    callback = opts;
    opts = {};
  }

  if (opts.crypto_dir && config.folders && config.folders[utils.md5Hash(opts.crypto_dir)]) {
    console.log('Use saved encryption key from config:', config_file);
    var ENC_KEY = config.folders[utils.md5Hash(opts.crypto_dir)].enc_key;
    return callback(null, ENC_KEY);
  }

  if (options.default && config.enc_key) {
    console.log('Use default encryption key from config:', config_file);
    return callback(null, config.enc_key);
  } else if (options.enc_key) {
    console.log('Use encryption key from arguments');
    return callback(null, options.enc_key);
  } else if (options.daemon && process.env.CF_DAEMON_ENC_KEY) {
    console.log('Use encryption key from env.CF_DAEMON_ENC_KEY');
    return callback(null, process.env.CF_DAEMON_ENC_KEY);
  } else if (options.passphrase) {
    console.log('Use passphrase from arguments');
    var ENC_KEY = cryptor.generateEncryptionKey(options.passphrase, crypto_salt, {algorithm: opts.algorithm});
    return callback(null, ENC_KEY);
  } else {
    cryptoUtils.getInputPassphrase(opts, function(err, passphrase) {
      if (err) {
        return callback(err);
      }
      var ENC_KEY = cryptor.generateEncryptionKey(passphrase, crypto_salt, {algorithm: opts.algorithm});
      return callback(null, ENC_KEY);
    });
  }
}

var getEncryptionKeyOrDie = function(opts, done) {
  getEncryptionKey(opts, function(err, enc_key) {
    if (err) {
      // console.log(err);
      console.log('');
      process.exit();
    }
    return done(enc_key);
  });
}

var loadCryptoFolderOrDie = function(cryptofolder, options, done) {
  console.log('Load crypto folder...');
  cryptofolder.load(options, function(err) {
    if (err) {
      console.log('Load crypto folder failed!');
      // console.log(err);
      console.log(chalk.red(err.message));
      process.exit();
    }
    console.log('Load crypto folder... Success');
    return done(err);
  })
}

var unloadCryptoFolder = function(cryptofolder, done) {
  console.log('Unload crypto folder...');
  cryptofolder.unload(function(err) {
    if (err) {
      console.log('Unload crypto folder failed!');
      // console.log(err);
      console.log(chalk.red(err.message));
    } else {
      console.log("Unloaded.");
    }
    return done(err);
  });
}

//// COMMAND HANDLERS

function cmdEncrypt(argv, callback) {
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
    console.log('Encrypt entries:');
    entries_to_encrypt.forEach(function(entry) {
      console.log('  -', entry+'*');
    });
  }

  var exit_callbacks = [];
  process.on('SIGINT', function () {
    console.log("\nCaught Ctrl^C");
    // 
    async.series(exit_callbacks, function(err) {
      process.exit();
    });
  });

  options.algorithm = options.algorithm || loadAlgorithmFromFolder(OUTPUT_DIR);
  if (options.algorithm) {
    console.log('Algorithm:', options.algorithm);
  }

  var verify_passphrase = true;
  if (utils.fileExists(path.join(OUTPUT_DIR, 'INDEX'))) {
    verify_passphrase = false;
  }

  getEncryptionKeyOrDie({
    verify: verify_passphrase, 
    crypto_dir: OUTPUT_DIR, 
    algorithm: options.algorithm
  }, function(enc_key) {

    var cryptofolder = new CryptoFolder(OUTPUT_DIR, enc_key, options.algorithm);

    if (options.algorithm) {
      saveAlgorithmToFolder(OUTPUT_DIR, options.algorithm);
    }
    
    var start_time = new Date();

    options.onFileEncrypt = function(original_file, encrypted_file, progress) {
      var elapsed_seconds = moment().diff(moment(start_time), 'seconds');
      log(chalk.magenta(utils.padLeft('Encrypting:',15)), 
        progress.current + '/' + progress.total, 
        '(' + bytes(progress.encrypted_size) + '/' + bytes(progress.total_size) + ')',
        chalk.grey(prettyMs(elapsed_seconds*1000)),
        utils.ellipsisMiddle(path.relative(INPUT_DIR, original_file.path),60), 
        chalk.magenta(bytes(original_file.size)));
    }
    options.onFileEncrypted = function(original_file, encrypted_file, progress) {
      var elapsed_seconds = moment().diff(moment(start_time), 'seconds');
      log(chalk.green(utils.padLeft('Encrypted:',15)), 
        progress.current + '/' + progress.total, 
        '(' + bytes(progress.encrypted_size) + '/' + bytes(progress.total_size) + ')',
        chalk.grey(prettyMs(elapsed_seconds*1000)),
        utils.ellipsisMiddle(path.relative(INPUT_DIR, original_file.path),60), 
        chalk.magenta(bytes(original_file.size)));
    }
    options.onFileEncryptFailed = function(err, original_file, encrypted_file, progress) {
      console.error(chalk.red(utils.padLeft('Encrypt failed:',15)), 
        progress.current + '/' + progress.total, 
        utils.ellipsisMiddle(original_file.path,60), 
        chalk.magenta(bytes(original_file.size)), 
        err.message);
    }

    // Load cryptofolder
    loadCryptoFolderOrDie(cryptofolder, options, function(err) {

      if (options.save_enc_key) {
        config.folders = config.folders || {};
        var input_dir_hash = utils.md5Hash(OUTPUT_DIR);
        if (!config.folders[input_dir_hash]) {
          config.folders[input_dir_hash] = {
            path: INPUT_DIR,
            enc_key: enc_key,
            added_at: new Date()
          };
          if (options.salt) {
            config.folders[input_dir_hash].salt = options.salt;
          }
          utils.saveToJsonFile(config, config_file);
          console.log('Encryption key saved.');
        }
      }

      exit_callbacks.push(function(cb) {
        unloadCryptoFolder(cryptofolder, cb);
      });

      // Encrypt files to cryptofolder
      cryptofolder.encrypt(INPUT_DIR, options, function(err, result) {
        if (err) {
          console.log('Encrypt folder failed!');
          console.log(err);
        } else if (result) {
          console.log('----');
          console.log('Directory:', result.dirs.length);

          console.log('Total:', result.files.length + ' file' + ((result.files.length != 1) ? 's.': '.'),
            result.total_size ? ' (' + bytes(result.total_size) + ').' : ''
          );
          console.log('New:', result.new_files.length + ' file' + ((result.new_files.length != 1) ? 's.': '.'),
            result.new_size ? ' (' + bytes(result.new_size) + ').' : ''
          );

          if (result.encrypted && result.encrypted.length) {
            console.log('Encrypted:', result.encrypted.length 
              + ' file' + ((result.encrypted.length != 1) ? 's': ''),
              result.encrypted_size ? ' (' + bytes(result.encrypted_size) + ').' : ''
            );
          }
          
          if (result.errors && result.errors.length) {
            console.log('----');
            console.log(chalk.red(result.errors.length + ' errors.'));
            result.errors.forEach(function(error) {
              console.log(error);
            });
          }
        }

        // Unload cryptofolder
        unloadCryptoFolder(cryptofolder, function(err) {
          process.exit();
        });
      });
    });
  });
}

function cmdDecrypt(argv, callback) {
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

  options.read_only = (!options.remove_source_files || options.remove_source_files.length == 0);

  options.algorithm = options.algorithm || loadAlgorithmFromFolder(INPUT_DIR);
  if (options.algorithm) {
    console.log('Algorithm:', options.algorithm);
  }

  getEncryptionKeyOrDie({crypto_dir: INPUT_DIR, algorithm: options.algorithm}, function(enc_key) {

    var input_dir_hash = utils.md5Hash(INPUT_DIR);
    if (options.save_enc_key) {
      config.folders = config.folders || {};
      if (!config.folders[input_dir_hash]) {
        config.folders[input_dir_hash] = {
          path: INPUT_DIR,
          enc_key: enc_key,
          added_at: new Date()
        };
        if (options.salt) {
          config.folders[input_dir_hash].salt = options.salt;
        }
        utils.saveToJsonFile(config, config_file);
        console.log('Encryption key saved.');
      }
    }

    var cryptofolder = new CryptoFolder(INPUT_DIR, enc_key, options.algorithm);

    options.onFileDecrypt = function(decrypted_file, encrypted_file, progress) {
      log(chalk.magenta('Decrypting:'), progress.current + '/' + progress.total, 
        '(' + bytes(progress.decrypted_size) + '/' + bytes(progress.total_size) + ')',
        utils.ellipsisMiddle(decrypted_file.path,60), chalk.magenta(bytes(decrypted_file.size)));
    }
    options.onFileDecrypted = function(decrypted_file, encrypted_file, progress) {
      log(chalk.green('Decrypted:'), progress.current + '/' + progress.total, 
        '(' + bytes(progress.decrypted_size) + '/' + bytes(progress.total_size) + ')',
        utils.ellipsisMiddle(decrypted_file.path,60), chalk.magenta(bytes(decrypted_file.size)));
    }
    options.onFileDecryptFailed = function(err, decrypted_file, encrypted_file, progress) {
      log(chalk.red('Decrypted failed:'), progress.current + '/' + progress.total, 
        utils.ellipsisMiddle(decrypted_file.path,60), chalk.magenta(bytes(decrypted_file.size)));
    }

    // Load cryptofolder
    loadCryptoFolderOrDie(cryptofolder, options, function(err) {

      // Decrypt files from cryptofolder
      cryptofolder.decrypt(OUTPUT_DIR, options, function(err, result) {
        if (err) {
          console.log('Decrypt crypto folder failed!');
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
        
        // Unload cryptofolder
        unloadCryptoFolder(cryptofolder, function(err) {
          process.exit();
        });
      });
    });
  });
}

function cmdRemove(argv, callback) {
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

  var entries_to_remove = [];
  if (argv.length > 1) {
    for (var i = 1; i < argv.length; i++) {
      entries_to_remove.push(argv[i]);
    }
  }
  if (entries_to_remove.length == 0) {
    console.log('Please provide entries to remove.');
    proces.exit();
  }
  console.log('Entries to remove (' + entries_to_remove.length + '):');
  entries_to_remove.forEach(function(entry) {
    console.log(' - ' + entry + '*');
  });

  options.algorithm = options.algorithm || loadAlgorithmFromFolder(INPUT_DIR);
  if (options.algorithm) {
    console.log('Algorithm:', options.algorithm);
  }

  getEncryptionKeyOrDie({crypto_dir: INPUT_DIR, algorithm: options.algorithm}, function(enc_key) {

    var cryptofolder = new CryptoFolder(INPUT_DIR, enc_key, options.algorithm);

    options.onFileRemove = function(decrypted_file, encrypted_file, progress) {
      log(chalk.magenta('Removing:'), progress.current + '/' + progress.total, 
        '(' + bytes(progress.removed_size) + '/' + bytes(progress.total_size) + ')',
        utils.ellipsisMiddle(decrypted_file.path,60), chalk.magenta(bytes(decrypted_file.size)));
    }
    options.onFileRemoved = function(decrypted_file, encrypted_file, progress) {
      log(chalk.green('Remove:'), progress.current + '/' + progress.total, 
        '(' + bytes(progress.removed_size) + '/' + bytes(progress.total_size) + ')',
        utils.ellipsisMiddle(decrypted_file.path,60), chalk.magenta(bytes(decrypted_file.size)));
    }
    options.onFileRemoveFailed = function(err, decrypted_file, encrypted_file, progress) {
      log(chalk.red('Remove failed:'), progress.current + '/' + progress.total, 
        utils.ellipsisMiddle(decrypted_file.path,60), chalk.magenta(bytes(decrypted_file.size)));
    }

    // Load cryptofolder
    loadCryptoFolderOrDie(cryptofolder, options, function(err) {

      // Remove files in cryptofolder
      cryptofolder.remove(entries_to_remove, options, function(err, result) {
        if (err) {
          console.log('Remove files in crypto folder failed!');
          console.log(err);
        } else if (result) {
          console.log('----');
          console.log('Total:', result.files.length + ' file' + ((result.files.length != 1) ? 's.': '.'));

          // console.log('Processed:', result.processed.length + ' file' + ((result.processed.length != 1) ? 's': '') 
          //   + ' (' + bytes(result.total_size) + ') processed.');

          if (result.removed && result.removed.length) {
            console.log('Removed:', result.removed.length 
              + ' file' + ((result.removed.length != 1) ? 's': '') 
              + ' (' + bytes(result.removed_size) + ').');
          }

          if (result.errors && result.errors.length) {
            console.log('----');
            console.log(chalk.red(result.errors.length + ' errors.'));
            result.errors.forEach(function(error) {
              console.log(error);
            });
          }
        }

        // Unload cryptofolder
        unloadCryptoFolder(cryptofolder, function(err) {
          process.exit();
        });
      });
    });
  });
}

function cmdList(argv, callback) {
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

  options.read_only = true;

  options.algorithm = options.algorithm || loadAlgorithmFromFolder(INPUT_DIR);
  if (options.algorithm) {
    console.log('Algorithm:', options.algorithm);
  }

  getEncryptionKeyOrDie({crypto_dir: INPUT_DIR, algorithm: options.algorithm}, function(enc_key) {

    var cryptofolder = new CryptoFolder(INPUT_DIR, enc_key, options.algorithm);

    // Load cryptofolder
    loadCryptoFolderOrDie(cryptofolder, options, function(err) {

      options.onFileInfo = function(file_info, index) {
        console.log(utils.padLeft(''+index, 6)+'.', 
          chalk.magenta(utils.padLeft(bytes(file_info.size), 8)), file_info.path);
      }

      // List files in cryptofolder
      cryptofolder.list(options, function(err, result) {
        if (err) {
          console.log('List files in crypto folder failed!');
          console.log(err);
        } else if (result) {
          console.log('----');
          console.log('Total files:', result.count);
          console.log('Total size:', bytes(result.total_size));
          if (result.largest_size>0) {
            console.log('Largest file:', chalk.magenta(bytes(result.largest_file.size)), result.largest_file.path);
          }
        }

        // Unload cryptofolder
        unloadCryptoFolder(cryptofolder, function(err) {
          process.exit();
        });
      });
    });
  });
}

function cmdBrowse(argv, callback) {
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

  options.read_only = true;
  
  var exit_callbacks = [];
  process.on('SIGINT', function () {
    console.log("\nCaught Ctrl^C");
    // 
    async.series(exit_callbacks, function(err) {
      process.exit();
    });
  });

  options.algorithm = options.algorithm || loadAlgorithmFromFolder(INPUT_DIR);
  if (options.algorithm) {
    console.log('Algorithm:', options.algorithm);
  }

  getEncryptionKeyOrDie({crypto_dir: INPUT_DIR, algorithm: options.algorithm}, function(enc_key) {

    var cryptofolder = new CryptoFolder(INPUT_DIR, enc_key, options.algorithm);

    // Load cryptofolder
    loadCryptoFolderOrDie(cryptofolder, options, function(err) {

      // Start browse cryptofolder
      cryptofolder.browse(options, function(err, listen_port) {
        if (err) {
          console.log('Browse crypto folder failed!');
          console.log(err);

          // Unload cryptofolder
          unloadCryptoFolder(cryptofolder, function(err) {
            process.exit();
          });
        } else {
          console.log('Crypto folder browser started. Listening on http://localhost:' + listen_port);

          exit_callbacks.push(function (cb) {
            // Unload cryptofolder
            unloadCryptoFolder(cryptofolder, function(err) {
              cb(err);
            });
          });
        }
      });
    });
  });
}

function cmdMount(argv, callback) {
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
  // options.mount_point = MOUNT_POINT;
  console.log('Mount point: ' + MOUNT_POINT);
  
  if (!options.read_write) options.read_only = true;

  var exit_callbacks = [];
  process.on('SIGINT', function () {
    console.log("\nCaught Ctrl^C");
    // 
    async.series(exit_callbacks, function(err) {
      if (err) console.log(err);
      console.log('Exited.');
      process.exit();
    });
  });

  options.algorithm = options.algorithm || loadAlgorithmFromFolder(INPUT_DIR);
  if (options.algorithm) {
    console.log('Algorithm:', options.algorithm);
  }

  getEncryptionKeyOrDie({crypto_dir: INPUT_DIR, algorithm: options.algorithm}, function(enc_key) {

    var cryptofolder = new CryptoFolder(INPUT_DIR, enc_key, options.algorithm);
      
    // Load cryptofolder
    loadCryptoFolderOrDie(cryptofolder, options, function(err) {

      if (options.daemon) {
        console.log('Using `umount` command to unmount.');

        process.env.CF_DAEMON_ENC_KEY = enc_key;

        require('daemon')();
      }

      options.onDestroy = function() {
        console.log('Crypto folder unmounted.');
        unloadCryptoFolder(cryptofolder, function(err) {
          process.exit();
        });
      }

      // Mount cryptofolder
      cryptofolder.mount(MOUNT_POINT, options, function(err, mount_point) {
        if (err) {
          console.log('Mount crypto folder failed!');
          console.log(err);

          // Unload cryptofolder
          unloadCryptoFolder(cryptofolder, function(err) {
            process.exit();
          });
        } else if (mount_point) {
          console.log('Crypto folder mounted on ' + mount_point.path);

          exit_callbacks.push(function(cb) {
            // Unload cryptofolder
            unloadCryptoFolder(cryptofolder, function(err) {
              cb();
            });
          });

          exit_callbacks.push(function(cb) {
            console.log("Unmounting...");
            // Unmount cryptofolder
            mount_point.unmount(function(err) {
              if (err) {
                console.log('Unmount failed!', mount_point.path);
                console.log('To to unmount manually, enter following command:');
                console.log('umount ' + mount_point.path);
              } else {
                console.log('Unmounted: ' + mount_point.path);
              }
              cb();
            });
          });
        }
      });
    });
  });
}

/// CONFIGURATIONS

function cmdConfigShow(argv, callback) {
  console.log(config);
  process.exit();
}

function cmdConfigSetSalt(argv, callback) {
  cryptoUtils.getInputSalt(function(err, salt) {
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
}

function cmdConfigSetEncryptionKey(argv, callback) {
  getEncryptionKeyOrDie({verify: true}, function(enc_key) {
    config.enc_key = enc_key;
    utils.saveToJsonFile(config, config_file);
    console.log('Config saved.');
    process.exit();
  });
}

function cmdConfigClearEncryptionKey(argv, callback) {
  delete config.enc_key;    
  utils.saveToJsonFile(config, config_file);
  console.log('Config saved.');
  process.exit();
}

function cmdGenerateEncryptionKey(arv, callback) {
  getEncryptionKeyOrDie({verify: true}, function(enc_key) {
    console.log('Encryption key:', enc_key);
  });
}

/// FOLDERS

function cmdFolderList(argv, callback) {
  var folder_list = [];
  if (config.folders) {
    for (var folder_id in config.folders) {
      folder_list.push(config.folders[folder_id]);
    }
  }

  if (options.sort_added) {
    folder_list.sort(function(a,b) {
      if (a.added_at>b.added_at) return 1;
      else if (a.added_at<b.added_at) return -1;
      return 0;
    });
  } else {
    folder_list.sort(function(a,b) {
      if (a.path>b.path) return 1;
      else if (a.path<b.path) return -1;
      return 0;
    });
  }

  if (folder_list.length == 0) {
    console.log('Folders list empty.');
    process.exit();
  } else {
    console.log('Folders:', folder_list.length);

    var exists_map = {};
    folder_list.forEach(function(folder, idx) {
      var folder_exists = utils.checkDirExists(folder.path, exists_map);
      console.log(chalk.bold(utils.padLeft(''+(idx+1), 3))+'.', 
        folder.path, 
        chalk.grey('(added ' + moment(folder.added_at).fromNow() + ')',
        (!folder_exists) ? chalk.red('(missing)') : ''));
    });
  }
}

function cmdFolderAdd(argv, callback) {
  if (argv.length == 0) {
    console.log('Usage: cryptofolder folder:add <encrypted-dir>');
    console.log('ERROR: Missing folder path');
    process.exit();
  }

  var folder_path = path.resolve(argv[0]);
  if (config.folders && config.folders[utils.md5Hash(folder_path)]) {
    console.log('Already added:', folder_path);
    process.exit();
  }

  options.read_only = true;

  options.algorithm = loadAlgorithmFromFolder(folder_path);
  if (options.algorithm) {
    console.log('Algorithm:', options.algorithm);
  }

  console.log('Adding folder...', folder_path);

  getEncryptionKeyOrDie({algorithm: options.algorithm}, function(enc_key) {

    var cryptofolder = new CryptoFolder(folder_path, enc_key, options.algorithm);
    // Load cryptofolder
    loadCryptoFolderOrDie(cryptofolder, options, function(err) {
      // Unload cryptofolder
      unloadCryptoFolder(cryptofolder, function(err) {
        config.folders = config.folders || {};
        config.folders[utils.md5Hash(folder_path)] = {
          path: folder_path,
          enc_key: enc_key,
          algorithm: options.algorithm,
          added_at: new Date()
        };

        console.log('Folder added.');

        utils.saveToJsonFile(config, config_file);
        console.log('Config saved.');
        process.exit();
      });
    });
  });
}

function cmdFolderRemove(argv, callback) {
  if (argv.length == 0) {
    console.log('Usage: cryptofolder folder:remove <encrypted-dir>');
    console.log('ERROR: Missing folder path');
    process.exit();
  }

  var folder_path = path.resolve(argv[0]);
  console.log('Removing folder:', folder_path);

  if (config.folders && config.folders[utils.md5Hash(folder_path)]) {
    delete config.folders[utils.md5Hash(folder_path)];
    console.log('Folder removed.');
    utils.saveToJsonFile(config, config_file);
    console.log('Config saved.');
    process.exit();
  } else {
    console.log('Folder not found in list.');
    process.exit();
  }
}

function cmdFolderMove(argv, callback) {
  if (argv.length < 2) {
    console.log('Usage: cryptofolder folder:move <old-path> <new-path>');
    process.exit();
  }

  var old_path = path.resolve(argv[0]);
  console.log('Move from path:', old_path);
  var new_path = path.resolve(argv[1]);
  console.log('To path:', new_path);

  if (config.folders) {
    var updated_folders = [];
    var update_folder_list = [];
    if (config.folders) {
      for (var folder_id in config.folders) {
        var folder_info = config.folders[folder_id];

        if (folder_info.path && folder_info.path.indexOf(old_path) == 0) {
          update_folder_list.push(folder_info);
        }
      }
    }

    if (update_folder_list.length > 0) {
      update_folder_list.forEach(function(folder) {
        var new_folder_path = folder.path.replace(old_path, new_path);

        if (new_folder_path != folder.path) {
          config.folders[utils.md5Hash(new_folder_path)] = { // add new entry
            path: new_folder_path,
            enc_key: folder.enc_key,
            added_at: folder.added_at || new Date()
          };

          console.log('Folder updated:', folder.path, '->', new_folder_path);
          updated_folders.push({
            old_path: folder.path, 
            new_path: new_folder_path
          });

          delete config.folders[utils.md5Hash(folder.path)]; // remove old entry
        }
      });

      console.log('Updated folders:', updated_folders.length);

      utils.saveToJsonFile(config, config_file);
      console.log('Config saved.');
    } else {
      console.log('No folders changed.');
    }

    process.exit();
  } else {
    console.log('No folders.');
    process.exit();
  }
}

/// TRASH

function cmdTrashList(argv, callback) {
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
  
  options.read_only = true;

  options.algorithm = options.algorithm || loadAlgorithmFromFolder(INPUT_DIR);
  if (options.algorithm) {
    console.log('Algorithm:', options.algorithm);
  }

  getEncryptionKeyOrDie({crypto_dir: INPUT_DIR, algorithm: options.algorithm}, function(enc_key) {

    var cryptofolder = new CryptoFolder(INPUT_DIR, enc_key, options.algorithm);

    // Load cryptofolder
    loadCryptoFolderOrDie(cryptofolder, options, function(err) {

      options.onFileInfo = function(file_info, index) {
        console.log(utils.padLeft(''+index, 6)+'.', 
          chalk.magenta(utils.padLeft(bytes(file_info.size), 8)), file_info.path);
      }

      // List files in cryptofolder's TRASH
      cryptofolder.listTrash(options, function(err, result) {
        if (err) {
          console.log('List files in crypto folder\'s trash failed!');
          console.log(err);
        } else if (result) {
          // console.log(result);
          console.log('----');
          console.log('Total files:', result.count);
          console.log('Total size:', bytes(result.total_size));
          if (result.largest_size>0) {
            console.log('Largest file:', chalk.magenta(bytes(result.largest_file.size)), result.largest_file.path);
          }
        }

        // Unload cryptofolder
        unloadCryptoFolder(cryptofolder, function(err) {
          process.exit();
        });
      });
    });
  });
}

function cmdTrashEmpty(argv, callback) {
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

  options.algorithm = options.algorithm || loadAlgorithmFromFolder(INPUT_DIR);
  if (options.algorithm) {
    console.log('Algorithm:', options.algorithm);
  }

  getEncryptionKeyOrDie({crypto_dir: INPUT_DIR, algorithm: options.algorithm}, function(enc_key) {

    var cryptofolder = new CryptoFolder(INPUT_DIR, enc_key, options.algorithm);

    // Load cryptofolder
    loadCryptoFolderOrDie(cryptofolder, options, function(err) {

      options.onFileRemoved = function(file, progress) {
        log(chalk.green('Removed:'), progress.current + '/' + progress.total, 
          '(' + bytes(progress.removed_size) + '/' + bytes(progress.total_size) + ')',
          utils.ellipsisMiddle(file.path,60), chalk.magenta(bytes(file.size)));
      }
      options.onFileRemoveFailed = function(err, file, progress) {
        log(chalk.red('Remove failed:'), progress.current + '/' + progress.total, 
          utils.ellipsisMiddle(file.path,60), chalk.magenta(bytes(file.size)));
      }

      console.log('Emptying trash...');
      // Empty cryptofolder's trash
      cryptofolder.emptyTrash(options, function(err, result) {
        if (err) {
          console.log('Empty crypto folder\'s trash failed!');
          console.log(err);
        } else if (result) {
          console.log('----');
          console.log('Total:', result.files.length + ' file' + ((result.files.length != 1) ? 's.': '.'));
          console.log('Total size:', bytes(result.totalSize));
        }

        // Unload cryptofolder
        unloadCryptoFolder(cryptofolder, function(err) {
          process.exit();
        });
      });
    });
  });
}

///// COMMAND MAPS

var command_map = {};

var bindCommandHandler = function(cmd, func) {
  if (!command_map[cmd]) {
    command_map[cmd] = func;
  }
}

bindCommandHandler('config:show', cmdConfigShow);
bindCommandHandler('config:set-salt', cmdConfigSetSalt);
bindCommandHandler('config:set-encryption-key', cmdConfigSetEncryptionKey);
bindCommandHandler('config:clear-encryption-key', cmdConfigClearEncryptionKey);

bindCommandHandler('gen-enc-key', cmdGenerateEncryptionKey);

bindCommandHandler('encrypt', cmdEncrypt);
bindCommandHandler('decrypt', cmdDecrypt);
bindCommandHandler('remove', cmdRemove);
bindCommandHandler('list', cmdList);
bindCommandHandler('browse', cmdBrowse);
bindCommandHandler('mount', cmdMount);

bindCommandHandler('folder:list', cmdFolderList);
bindCommandHandler('folder:add', cmdFolderAdd);
bindCommandHandler('folder:remove', cmdFolderRemove);
bindCommandHandler('folder:move', cmdFolderMove);

bindCommandHandler('trash:list', cmdTrashList);
bindCommandHandler('trash:empty', cmdTrashEmpty);

/////
if (typeof command_map[command] == 'function') {
  command_map[command](argv, function(err) {
    if (err) {
      console.log(err);
      process.exit(1);
    } else {
      process.exit();
    }
  });
} else {
  printUsage();
  process.exit();
}
