#!/usr/bin/env node

var fs = require('fs');
var path = require('path');

var async = require('async');
var fse = require('fs-extra');
var chalk = require('chalk');
var bytes = require('bytes');

var log = require('single-line-log').stdout;

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
  console.log('       cryptofolder mount [OPTIONS] <encrypted-dir> <mount-point>');
  console.log('');
  console.log('       cryptofolder config');
  console.log('       cryptofolder config --set-passphrase');
  console.log('       cryptofolder config --set-salt');
  console.log('       cryptofolder config --clear-encryption-key');
  console.log('       cryptofolder gen-enc-key');
  console.log('');
  console.log('OPTIONS:');
  console.log('');
  console.log('     --force                   -f');
  console.log('     --verbose                 -v');
  console.log('');
  console.log('     --default                 -d    : use default encryption key (if exists)');
  console.log('     --enc-key=STRING                : custom encryption key');
  console.log('');
  console.log('     --recursive               -r    : scan input directory recursively (default: yes)');
  console.log('     --no-recursive            -n    : only scan input directory (not recursively)');
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

var crypto_salt = options.salt || config.salt || 'jul11co-crypto-tools';

var getEncryptionKey = function(opts, callback) {
  if (typeof opts == 'function') {
    callback = opts;
    opts = {};
  }

  if ((options.default && config.enc_key) || options.enc_key) {
    return callback(null, options.enc_key || config.enc_key);
  } else if (options.passphrase) {
    var ENC_KEY = cryptoUtils.generateEncryptionKey(options.passphrase, crypto_salt);
    return callback(null, ENC_KEY);
  } else {
    cryptoUtils.getPromptPassphrase(opts, function(err, passphrase) {
      if (err) {
        return callback(err);
      }
      var ENC_KEY = cryptoUtils.generateEncryptionKey(passphrase, crypto_salt);
      return callback(null, ENC_KEY);
    });
  }
}

/////

if (command == 'config') {
  if (options.set_passphrase) {
    getEncryptionKey({verify: true}, function(err, enc_key) {
      if (err) {
        // console.log(err);
        console.log('');
        process.exit();
      }
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
    cryptoUtils.getPromptSalt(function(err, salt) {
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
} else if (command == 'gen-enc-key') {
  getEncryptionKey({verify: true}, function(err, enc_key) {
    if (err) {
      // console.log(err);
      process.exit();
    }
    console.log('Encryption key:', enc_key);
    var index_verify_string = cryptor.encryptString('jul11co-crypto-index', enc_key);
    console.log('Index verify string:', index_verify_string);
  });
} else if (command == 'encrypt') {
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

  getEncryptionKey({verify: true}, function(err, enc_key) {
    if (err) {
      // console.log(err);
      console.log('');
      process.exit();
    }

    var cryptofolder = new CryptoFolder(OUTPUT_DIR, enc_key);
      
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

    // Load cryptofolder
    cryptofolder.load(options, function(err) {
      if (err) {
        console.log('Load crypto folder failed!');
        // console.log(err);
        console.log(chalk.red(err.message));
        process.exit();
      }

      process.on('SIGINT', function() {
        console.log("\nCaught interrupt signal");
        cryptofolder.unload(function(err) {
          if (err) {
            console.log('Unload crypto folder failed!');
            console.log(err);
          }
          process.exit();
        });
      });

      // Encrypt files to cryptofolder
      cryptofolder.encrypt(INPUT_DIR, options, function(err, result) {
        if (err) {
          console.log('Encrypt folder failed!');
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

        // Unload cryptofolder
        cryptofolder.unload(function(err) {
          if (err) {
            console.log('Unload crypto folder failed!');
            console.log(err);
          }
          process.exit();
        });
      });
    });
  });
} else if (command == 'decrypt') {
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

  getEncryptionKey(function(err, enc_key) {
    if (err) {
      // console.log(err);
      console.log('');
      process.exit();
    }

    var cryptofolder = new CryptoFolder(INPUT_DIR, enc_key);

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

    // Load cryptofolder
    cryptofolder.load(options, function(err) {
      if (err) {
        console.log('Load crypto folder failed!');
        // console.log(err);
        console.log(chalk.red(err.message));
        process.exit();
      }

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
        cryptofolder.unload(function(err) {
          if (err) {
            console.log('Unload crypto folder failed!');
            console.log(err);
          }
          process.exit();
        });
      });
    });
  });
} else if (command == 'remove') {
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

  getEncryptionKey(function(err, enc_key) {
    if (err) {
      // console.log(err);
      console.log('');
      process.exit();
    }

    var cryptofolder = new CryptoFolder(INPUT_DIR, enc_key);

    options.onFileRemove = function(decrypted_file, encrypted_file, progress) {
      log(chalk.magenta('Removing:'), progress.current + '/' + progress.total, 
        utils.ellipsisMiddle(decrypted_file.path,60), chalk.magenta(bytes(decrypted_file.size)));
    }
    options.onFileRemoved = function(decrypted_file, encrypted_file, progress) {
      log(chalk.green('Remove:'), progress.current + '/' + progress.total, 
        utils.ellipsisMiddle(decrypted_file.path,60), chalk.magenta(bytes(decrypted_file.size)));
    }
    options.onFileRemoveFailed = function(err, decrypted_file, encrypted_file, progress) {
      log(chalk.red('Remove failed:'), progress.current + '/' + progress.total, 
        utils.ellipsisMiddle(decrypted_file.path,60), chalk.magenta(bytes(decrypted_file.size)));
    }

    // Load cryptofolder
    cryptofolder.load(options, function(err) {
      if (err) {
        console.log('Load crypto folder failed!');
        // console.log(err);
        console.log(chalk.red(err.message));
        process.exit();
      }

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
        cryptofolder.unload(function(err) {
          if (err) {
            console.log('Unload crypto folder failed!');
            console.log(err);
          }
          process.exit();
        });
      });
    });
  });

} else if (command == 'list') {
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

  getEncryptionKey(function(err, enc_key) {
    if (err) {
      // console.log(err);
      console.log('');
      process.exit();
    }

    var cryptofolder = new CryptoFolder(INPUT_DIR, enc_key);

    // Load cryptofolder
    cryptofolder.load(options, function(err) {
      if (err) {
        console.log('Load crypto folder failed!');
        // console.log(err);
        console.log(chalk.red(err.message));
        process.exit();
      }

      options.onFileInfo = function(file_info, index) {
        console.log(utils.padLeft(''+index, 6)+'.', 
          chalk.magenta(utils.padLeft(bytes(file_info.s), 8)), file_info.p);
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
        cryptofolder.unload(function(err) {
          if (err) {
            console.log('Unload crypto folder failed!');
            console.log(err);
          }
          process.exit();
        });
      });
    });
  });
} else if (command == 'browse') {
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

  getEncryptionKey(function(err, enc_key) {
    if (err) {
      // console.log(err);
      console.log('');
      process.exit();
    }

    var cryptofolder = new CryptoFolder(INPUT_DIR, enc_key);

    // Load cryptofolder
    cryptofolder.load(options, function(err) {
      if (err) {
        console.log('Load crypto folder failed!');
        // console.log(err);
        console.log(chalk.red(err.message));
        process.exit();
      }

      // Start browse cryptofolder
      cryptofolder.browse(options, function(err, listen_port) {
        if (err) {
          console.log('Browse crypto folder failed!');
          console.log(err);

          // Unload cryptofolder
          cryptofolder.unload(function(err) {
            if (err) {
              console.log('Unload crypto folder failed!');
              console.log(err);
            }
            process.exit();
          });
        } else {
          console.log('Crypto folder browser started. Listening on http://localhost:' + listen_port);

          exit_callbacks.push(function (cb) {
            console.log("\nUnloading...");
            // Unload cryptofolder
            cryptofolder.unload(function(err) {
              if (err) {
                console.log('Unload crypto folder failed!');
                console.log(err);
              } else {
                console.log("Unloaded.");
              }
              cb(err);
            });
          });
        }
      });
    });
  });
} else if (command == 'mount') {
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
      process.exit();
    });
  });

  getEncryptionKey(function(err, enc_key) {
    if (err) {
      // console.log(err);
      console.log('');
      process.exit();
    }

    var cryptofolder = new CryptoFolder(INPUT_DIR, enc_key);
      
    // Load cryptofolder
    cryptofolder.load(options, function(err) {
      if (err) {
        console.log('Load crypto folder failed!');
        // console.log(err);
        console.log(chalk.red(err.message));
        process.exit();
      }

      // Mount cryptofolder
      cryptofolder.mount(MOUNT_POINT, options, function(err, mount_point) {
        if (err) {
          console.log('Mount crypto folder failed!');
          console.log(err);

          // Unload cryptofolder
          cryptofolder.unload(function(err) {
            if (err) {
              console.log('Unload crypto folder failed!');
              console.log(err);
            }
            process.exit();
          });
        } else if (mount_point) {
          console.log('Crypto folder mounted on ' + mount_point.path);

          var unMountOnExit = function(cb) {
            console.log("Unmounting...");
            // Unmount cryptofolder
            mount_point.unmount(function(err) {
              if (err) {
                console.log('Unmount failed!', mount_point.path);
              } else {
                console.log('Unmounted: ' + mount_point.path);
              }
              cb();
            });
          }

          var unloadFolderOnExit = function(cb) {
            console.log("Unload cryptofolder...");
            // Unload cryptofolder
            cryptofolder.unload(function(err) {
              if (err) {
                console.log('Unload crypto folder failed!');
                console.log(err);
              } else {
                console.log("Unload cryptofolder... OK");
              }
              cb();
            });
          }

          exit_callbacks.push(unloadFolderOnExit);
          exit_callbacks.push(unMountOnExit);
        }
      });
    });
  });
} else {
  printUsage();
  process.exit();
}
