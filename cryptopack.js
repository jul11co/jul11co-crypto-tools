#!/usr/bin/env node

var path = require('path');

var fse = require('fs-extra');
var chalk = require('chalk');
var bytes = require('bytes');

var utils = require('./lib/utils');
var cryptor = require('./lib/cryptor');

var log = require('single-line-log').stdout;

var cryptoUtils = require('./lib/crypto-utils');
var CryptoPack = require('./lib/crypto-pack');

var VERSION = '0.0.3';

function printUsage() {
  console.log('cryptopack - version ' + VERSION + ', cryptor - version ' + cryptor.getVersion());
  console.log('');
  console.log('Usage:');
  console.log('       cryptopack create [OPTIONS] <input-dir> [output-pack | output-dir]');
  console.log('       cryptopack extract [OPTIONS] <input-pack> [output-dir] [entries...]');
  console.log('       cryptopack list [OPTIONS] <input-pack> [entries...]');
  console.log('       cryptopack index [OPTIONS] <input-pack>');
  console.log('       cryptopack browse [OPTIONS] <input-pack>');
  console.log('       cryptopack mount [OPTIONS] <input-pack> <mount-point>');
  console.log('');
  console.log('       cryptopack config');
  console.log('       cryptopack config --set-passphrase');
  console.log('       cryptopack config --set-salt');
  console.log('       cryptopack config --clear-encryption-key');
  console.log('       cryptopack gen-enc-key');
  console.log('');
  console.log('OPTIONS:');
  console.log('');
  console.log('     --force                   -f    : force replace or update existing pack file');
  console.log('     --verbose                 -v    : verbose');
  console.log('     --progress                      : show progress');
  console.log('');
  console.log('     --recursive               -r    : scan input directory recursively (default: yes)');
  console.log('     --no-recursive            -n    : only scan input directory (not recursively)');
  console.log('');
  console.log('     --default                 -d    : use default encryption key (if exists)');
  console.log('     --enc-key=STRING                : custom encryption key');
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
var options = { recursive: true };
for (var i = 3; i < process.argv.length; i++) {
  if (process.argv[i] == '--default' || process.argv[i] == '-d') {
    options.default = true;
  } else if (process.argv[i] == '--ignore-errors') {
    options.ignore_errors = true;
  } else if (process.argv[i] == '--stop-if-errors' || process.argv[i] == '-e') {
    options.ignore_errors = false;
  } else if (process.argv[i] == '--recursive' || process.argv[i] == '-r') {
    options.recursive = true;
  } else if (process.argv[i] == '--no-recursive' || process.argv[i] == '-n') {
    options.recursive = false;
  } else if (process.argv[i] == '--force' || process.argv[i] == '-f') {
    options.force = true;
  } else if (process.argv[i] == '--verbose' || process.argv[i] == '-v') {
    options.verbose = true;
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
  console.log('cryptopack - version ' + VERSION + ', cryptor - version ' + cryptor.getVersion());
  process.exit();
}

if (options.salt) {
  console.log('Custom salt:', options.salt);
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
  } else if (options.set_salt) {
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
  });
} else if (command == 'create') {
  if (argv.length < 1) {
    printUsage();
    process.exit();
  }

  var INPUT_DIR = path.resolve(argv[0]);
  if (!utils.directoryExists(INPUT_DIR)) {
    console.log('Directory not found:', INPUT_DIR);
    process.exit();
  }
  console.log('Input directory: ' + INPUT_DIR 
    + (options.recursive ? chalk.magenta(' (recursive)') : chalk.yellow(' (without recursive)')));
  options.input_dir = INPUT_DIR;

  var default_output_pack = path.join(path.dirname(INPUT_DIR), path.basename(INPUT_DIR) + '.cryptopack');
  var OUTPUT_PACK = default_output_pack;
  if (argv[1] && utils.directoryExists(path.resolve(argv[1]))) {
    var output_dir = path.resolve(argv[1]);
    OUTPUT_PACK = path.join(output_dir, path.basename(INPUT_DIR) + '.cryptopack');
  } else if (argv[1]) {
    OUTPUT_PACK = path.resolve(argv[1]);
  }

  if (!options.force && utils.fileExists(OUTPUT_PACK)) {
    console.log(chalk.red('Cryptopack exists:'), OUTPUT_PACK);
    console.log(chalk.grey('Hint: Add --force or -f to update existing cryptopack.'));
    process.exit();
  }
  console.log('Cryptopack: ' + OUTPUT_PACK);

  getEncryptionKey({verify: true}, function(err, enc_key) {
    if (err) {
      // console.log(err);
      console.log('');
      process.exit();
    }

    var cryptopack = new CryptoPack(OUTPUT_PACK, enc_key);
    
    options.onFileEncrypt = function(original_file, encrypted_file, progress) {
      log(chalk.magenta('Encrypt:'), progress.current + '/' + progress.total, 
        path.relative(INPUT_DIR, original_file.path), chalk.magenta(bytes(original_file.size)));
    }
    options.onFileEncrypted = function(original_file, encrypted_file, progress) {
      log(chalk.green('Encrypted:'), progress.current + '/' + progress.total, 
        path.relative(INPUT_DIR, original_file.path), chalk.magenta(bytes(original_file.size)));
    }
    options.onFileEncryptFailed = function(err, original_file, encrypted_file, progress) {
      log(chalk.red('Encrypt failed:'), progress.current + '/' + progress.total, 
        original_file.path, chalk.magenta(bytes(original_file.size)), err.message);
    }

    cryptopack.load(options, function(err) {
      if (err) {
        console.log('Load crypto pack failed!');
        // console.log(err);
        console.log(chalk.red(err.message));
        process.exit();
      }

      process.on('SIGINT', function() {
        console.log("\nCaught interrupt signal");
        cryptopack.unload(function(err) {
          if (err) {
            console.log('Unload crypto pack failed!');
            console.log(err);
          }
          process.exit();
        })
      });

      cryptopack.pack(INPUT_DIR, options, function(err, result) {
        if (err) {
          console.log('Encrypt folder error!');
          console.log(err);
        } else if (result) {
          console.log('----');
          console.log('Directory:', result.dirs.length + ' director' + ((result.dirs.length != 1) ? 'ies.': 'y.'));
          console.log('Total:', result.files.length + ' file' + ((result.files.length != 1) ? 's.': '.'));

          // console.log(result.processed.length + ' file' + ((result.processed.length != 1) ? 's': '') 
          //   + ' (' + bytes(result.total_size) + ') processed.');

          if (result.encrypted && result.encrypted.length) {
            console.log('Encrypted:', chalk.magenta(result.encrypted.length 
              + ' file' + ((result.encrypted.length != 1) ? 's': '') 
              + ' (' + bytes(result.encrypted_size) + ').'));
          }

          if (result.errors && result.errors.length) {
            console.log('----');
            console.log(chalk.red(errors.length + ' errors.'));
            result.errors.forEach(function(error) {
              console.log(error);
            });
          }
        }
        
        cryptopack.unload(function(err) {
          if (err) {
            console.log('Unload crypto pack failed!');
            console.log(err);
          } else if (result) {
            if (result.updated) {
              console.log('Updating existing cryptopack... OK');
              console.log('Cryptopack updated:', OUTPUT_PACK, 
                chalk.magenta(result.stats ? bytes(result.stats['size']) : ''));
            } else if (result.created) {
              console.log('Creating new cryptopack... OK');
              console.log('Cryptopack created:', OUTPUT_PACK, 
                chalk.magenta(result.stats ? bytes(result.stats['size']) : ''));
            }
          }
          process.exit();
        })
      });
    });
  });
} else if (command == 'extract') {
  if (argv.length < 1) {
    printUsage();
    process.exit();
  }

  var INPUT_PACK = path.resolve(argv[0]);
  if (!utils.fileExists(INPUT_PACK)) {
    console.log(chalk.red('Cryptopack not found:'), INPUT_PACK);
    process.exit();
  }
  console.log('Cryptopack: ' + INPUT_PACK);

  var default_output_dir = path.join(path.dirname(INPUT_PACK), path.basename(INPUT_PACK, path.extname(INPUT_PACK)));
  var OUTPUT_DIR = argv[1] ? path.resolve(argv[1]) : default_output_dir;
  if (!options.force && utils.directoryExists(OUTPUT_DIR)) {
    console.log(chalk.red('Directory exists:'), OUTPUT_DIR);
    console.log(chalk.grey('Hint: Add --force or -f to merge/replace files in existing directory.'));
    process.exit();
  }
  console.log('Extract to: ' + OUTPUT_DIR);
  options.output_dir = OUTPUT_DIR;

  var entries_to_extract = [];
  if (argv.length > 2) {
    for (var i = 2; i < argv.length; i++) {
      entries_to_extract.push(argv[i]);
    }
  }
  if (entries_to_extract.length) {
    options.extract_entries = entries_to_extract;
  }

  options.read_only = true;

  getEncryptionKey(function(err, enc_key) {
    if (err) {
      // console.log(err);
      console.log('');
      process.exit();
    }

    var cryptopack = new CryptoPack(INPUT_PACK, enc_key);
    
    if (options.progress) {
      options.onEntry = function(entry) {
        console.log((entry.type || 'File')[0], entry.path, chalk.magenta(bytes(entry.size)));
      }
    }

    options.onFileDecrypt = function(decrypted_file, encrypted_file, progress) {
      log(chalk.magenta('Decrypt:'), progress.current + '/' + progress.total, 
        decrypted_file.path, chalk.magenta(bytes(decrypted_file.size)));
    }
    options.onFileDecrypted = function(decrypted_file, encrypted_file, progress) {
      log(chalk.green('Decrypted:'), progress.current + '/' + progress.total, 
        decrypted_file.path, chalk.magenta(bytes(decrypted_file.size)));
    }
    options.onFileDecryptFailed = function(err, decrypted_file, encrypted_file, progress) {
      log(chalk.red('Decrypted failed:'), progress.current + '/' + progress.total, 
        decrypted_file.path, chalk.magenta(bytes(decrypted_file.size)));
    }

    cryptopack.load(options, function(err) {
      if (err) {
        console.log('Load crypto pack failed!');
        // console.log(err);
        console.log(chalk.red(err.message));
        process.exit();
      }

      process.on('SIGINT', function() {
        console.log("\nCaught interrupt signal");
        cryptopack.unload(function(err) {
          if (err) {
            console.log('Unload crypto pack failed!');
            console.log(err);
          }
          process.exit();
        })
      });

      cryptopack.extract(OUTPUT_DIR, options, function(err, result) {
        if (err) {
          console.log('Extract crypto pack failed!');
          console.log(err);
        } else if (result) {
          console.log('----');
          console.log('Total:', result.files.length + ' file' + ((result.files.length != 1) ? 's.': '.'));

          // console.log(result.processed.length + ' file' + ((result.processed.length != 1) ? 's': '') 
          //   + ' (' + bytes(result.total_size) + ') processed.');

          if (result.decrypted && result.decrypted.length) {
            console.log('Decrypted:', chalk.magenta(result.decrypted.length 
              + ' file' + ((result.decrypted.length != 1) ? 's': '') 
              + ' (' + bytes(result.decrypted_size) + ').'));
          }
          
          if (result.errors && result.errors.length) {
            console.log('----');
            console.log(chalk.red(result.errors.length + ' errors.'));
            result.errors.forEach(function(error) {
              console.log(error);
            });
          }
        }
      
        cryptopack.unload(function(err) {
          if (err) {
            console.log('Unload crypto pack failed!');
            console.log(err);
          }
          process.exit();
        })
      });
    });
  });
} else if (command == 'list') {
  if (argv.length < 1) {
    printUsage();
    process.exit();
  }

  var INPUT_PACK = path.resolve(argv[0]);
  if (!utils.fileExists(INPUT_PACK)) {
    console.log(chalk.red('Cryptopack not found:'), INPUT_PACK);
    process.exit();
  }
  console.log('Cryptopack: ' + INPUT_PACK);

  var entries_to_list = [];
  if (argv.length > 1) {
    for (var i = 1; i < argv.length; i++) {
      entries_to_list.push(argv[i]);
    }
  }
  if (entries_to_list.length) {
    options.list_entries = entries_to_list;
  }

  getEncryptionKey(function(err, enc_key) {
    if (err) {
      // console.log(err);
      console.log('');
      process.exit();
    }

    var cryptopack = new CryptoPack(INPUT_PACK, enc_key);

    cryptopack.load(options, function(err) {
      if (err) {
        console.log('Load crypto pack failed!');
        // console.log(err);
        console.log(chalk.red(err.message));
        process.exit();
      }

      process.on('SIGINT', function() {
        console.log("\nCaught interrupt signal");
        cryptopack.unload(function(err) {
          if (err) {
            console.log('Unload crypto pack failed!');
            console.log(err);
          }
          process.exit();
        })
      });

      options.onFileInfo = function(file_info, index) {
        console.log(utils.padLeft(''+count, 6)+'.', 
          chalk.magenta(utils.padLeft(bytes(file_info.s), 8)), file_info.p);
      }

      cryptopack.list(options, function(err, result) {
        if (err) {
          console.log('List files from crypto pack failed!');
          console.log(err);
        } if (result) {
          console.log('----');
          console.log('Total files:', result.count);
          console.log('Total size:', bytes(result.total_size));

          if (result.largest_size>0) {
            console.log('Largest file:', chalk.magenta(bytes(result.largest_file.size)), result.largest_file.path);
          }
        }

        cryptopack.unload(function(err) {
          if (err) {
            console.log('Unload crypto pack failed!');
            console.log(err);
          }
          process.exit();
        })
      });
    });
  });
} else if (command == 'browse') {
  if (argv.length < 1) {
    printUsage();
    process.exit();
  }

  var INPUT_PACK = path.resolve(argv[0]);
  if (!utils.fileExists(INPUT_PACK)) {
    console.log(chalk.red('Cryptopack not found:'), INPUT_PACK);
    process.exit();
  }
  console.log('Cryptopack: ' + INPUT_PACK);

  options.read_only = true;

  getEncryptionKey(function(err, enc_key) {
    if (err) {
      // console.log(err);
      console.log('');
      process.exit();
    }

    var cryptopack = new CryptoPack(INPUT_PACK, enc_key);

    cryptopack.load(options, function(err) {
      if (err) {
        console.log('Load crypto pack failed!');
        // console.log(err);
        console.log(chalk.red(err.message));
        process.exit();
      }

      process.on('SIGINT', function() {
        console.log("\nCaught interrupt signal");
        cryptopack.unload(function(err) {
          if (err) {
            console.log('Unload crypto pack failed!');
            console.log(err);
          }
          process.exit();
        })
      });

      cryptopack.browse(options, function(err, listen_port) {
        if (err) {
          console.log('Browse crypto pack failed!');
          console.log(err);

          // Unload cryptopack
          cryptopack.unload(function(err) {
            if (err) {
              console.log('Unload crypto pack failed!');
              console.log(err);
            }
            process.exit();
          })
        } else {
          console.log('Crypto pack browser started. Listening on http://localhost:' + listen_port);

          process.on('SIGINT', function () {
            console.log("\nCaught interrupt signal");
            // Unload cryptopack
            cryptopack.unload(function(err) {
              if (err) {
                console.log('Unload crypto pack failed!');
                console.log(err);
              }
              process.exit();
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

  var INPUT_PACK = path.resolve(argv[0]);
  if (!utils.fileExists(INPUT_PACK)) {
    console.log(chalk.red('Cryptopack not found:'), INPUT_PACK);
    process.exit();
  }
  console.log('Cryptopack: ' + INPUT_PACK);

  var MOUNT_POINT = path.resolve(argv[1]);
  options.mount_point = MOUNT_POINT;
  console.log('Mount point: ' + MOUNT_POINT);
  
  options.read_only = true;

  getEncryptionKey(function(err, enc_key) {
    if (err) {
      // console.log(err);
      console.log('');
      process.exit();
    }

    var cryptopack = new CryptoPack(INPUT_PACK, enc_key);
    
    cryptopack.load(options, function(err) {
      if (err) {
        console.log('Load crypto pack failed!');
        // console.log(err);
        console.log(chalk.red(err.message));
        process.exit();
      }

      process.on('SIGINT', function() {
        console.log("\nCaught interrupt signal");
        cryptopack.unload(function(err) {
          if (err) {
            console.log('Unload crypto pack failed!');
            console.log(err);
          }
          process.exit();
        })
      });

      cryptopack.mount(MOUNT_POINT, options, function(err, mount_point) {
        if (err) {
          console.log('Mount crypto pack failed!');
          console.log(err);

          // Unload cryptopack
          cryptopack.unload(function(err) {
            if (err) {
              console.log('Unload crypto pack failed!');
              console.log(err);
            }
            process.exit();
          });
        } else if (mount_point) {
          console.log('Crypto pack mounted on ' + mount_point.path);

          process.on('SIGINT', function () {
            console.log("\nCaught interrupt signal");

            // Unmount cryptopack
            mount_point.unmount(function(err) {
              if (err) {
                console.log('Unmount failed!', mount_point.path)
              } else {
                console.log('Unmounted: ' + mount_point.path);
              }

              // Unload cryptopack
              cryptopack.unload(function(err) {
                if (err) {
                  console.log('Unload crypto pack failed!');
                  console.log(err);
                }
                process.exit();
              });
            });
          });
        }
      });
    });
  });
} else if (command == 'index') {
  if (argv.length < 1) {
    printUsage();
    process.exit();
  }

  var INPUT_PACK = path.resolve(argv[0]);
  if (!utils.fileExists(INPUT_PACK)) {
    console.log(chalk.red('Cryptopack not found:'), INPUT_PACK);
    process.exit();
  }
  console.log('Cryptopack: ' + INPUT_PACK);
  
  if (options.progress) {
    options.onEntry = function(entry) {
      console.log((entry.type || 'File')[0], entry.name || entry.path, chalk.magenta(bytes(entry.size)));
    }
  }

  options.index_file = argv[1];

  var cryptopack = new CryptoPack(INPUT_PACK);

  cryptopack.load(options, function(err) {
    if (err) {
      console.log('Load crypto pack failed!');
      // console.log(err);
      console.log(chalk.red(err.message));
      process.exit();
    }

    cryptopack.index(options, function(err, result) {
      if (err) {
        console.log(err);
      } else if (result) {
        if (result.index_stats) {
          console.log('Entries count:', result.index_stats.entriesCount);
          console.log('Total size:', bytes(result.index_stats.totalSize));
        }
        if (result.index_file_stats) {
          console.log('Index file created:', idx_file, bytes(stat['size']));
        } else {
          console.log('Cannot generate index file!', idx_file);
        }
      }

      cryptopack.unload(function(err) {
        if (err) {
          console.log('Unload crypto pack failed!');
          console.log(err);
        }
        process.exit();
      });
    });
  });

} else {
  printUsage();
  process.exit();
}
