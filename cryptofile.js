#!/usr/bin/env node

var path = require('path');

var fse = require('fs-extra');
var chalk = require('chalk');
var bytes = require('bytes');

var utils = require('./lib/utils');
var cryptor = require('./lib/cryptor');

var log = require('single-line-log').stdout;

var cryptoUtils = require('./lib/crypto-utils');
var CryptoFile = require('./lib/crypto-file');

var VERSION = '0.0.2';

function printUsage() {
  console.log('cryptofile - version ' + VERSION + ', cryptor - version ' + cryptor.getVersion());
  console.log('');
  console.log('Usage:');
  console.log('       cryptofile encode [OPTIONS] <input-file> [encrypted-file]');
  console.log('       cryptofile decode [OPTIONS] <encrypted-file> [output-file]');
  console.log('       cryptofile info [OPTIONS] <encrypted-file>');
  console.log('');
  console.log('       cryptofile config');
  console.log('       cryptofile config --set-passphrase');
  console.log('       cryptofile config --set-salt');
  console.log('       cryptofile config --clear-encryption-key');
  console.log('       cryptofile gen-enc-key');
  console.log('');
  console.log('OPTIONS:');
  console.log('');
  console.log('     --default                 -d    : use default encryption key (if exists)');
  console.log('     --enc-key=STRING                : custom encryption key');
  console.log('');
  console.log('     --force                   -f    : force replace or update existing file');
  console.log('     --verbose                 -v    : verbose');
  console.log('');
}

if (process.argv.length < 3 || process.argv.indexOf('--help') >= 0) {
  printUsage();
  process.exit();
}

var command = process.argv[2];
var argv = [];
var options = {};
for (var i = 3; i < process.argv.length; i++) {
  if (process.argv[i] == '--default' || process.argv[i] == '-d') {
    options.default = true;
  } else if (process.argv[i] == '--ignore-errors') {
    options.ignore_errors = true;
  } else if (process.argv[i] == '--stop-if-errors' || process.argv[i] == '-e') {
    options.ignore_errors = false;
  } else if (process.argv[i] == '--force' || process.argv[i] == '-f') {
    options.force = true;
  } else if (process.argv[i] == '--verbose' || process.argv[i] == '-v') {
    options.verbose = true;
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
  console.log('cryptofile - version ' + VERSION + ', cryptor - version ' + cryptor.getVersion());
  process.exit();
}

if (options.salt) {
  console.log('Custom salt:', options.salt);
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
  });
} else if (command == 'encode') {
  if (argv.length < 1) {
    printUsage();
    process.exit();
  }

  var INPUT_FILE = path.resolve(argv[0]);
  if (!utils.fileExists(INPUT_FILE)) {
    console.log('File not found:', INPUT_FILE);
    process.exit();
  }
  console.log('Input file: ' + INPUT_FILE);

  var default_output_file = path.join(path.dirname(INPUT_FILE), path.basename(INPUT_FILE) + '.cryptofile');
  var OUTPUT_FILE = (argv[1]) ? path.resolve(argv[1]) : default_output_file;

  if (!options.force && utils.fileExists(OUTPUT_FILE)) {
    console.log(chalk.red('Cryptofile exists:'), OUTPUT_FILE);
    console.log(chalk.grey('Hint: Add --force or -f to overwrite existing cryptofile.'));
    process.exit();
  }
  console.log('Encode to: ' + OUTPUT_FILE);

  getEncryptionKey({verify: true}, function(err, enc_key) {
    if (err) {
      // console.log(err);
      console.log('');
      process.exit();
    }

    var cryptofile = new CryptoFile(OUTPUT_FILE, enc_key);

    if (options.progress) {
      options.onEntry = function(entry) {
        console.log((entry.type || 'File')[0], entry.path, chalk.magenta(bytes(entry.size)));
      }
    }

    cryptofile.load(function(err) {
      if (err) {
        console.log('Load crypto file failed!');
        // console.log(err);
        console.log(chalk.red(err.message));
        process.exit();
      }

      process.on('SIGINT', function() {
        console.log("\nCaught interrupt signal");
        cryptofile.unload(function(err) {
          if (err) {
            console.log('Unload crypto file failed!');
            console.log(err);
          }
          process.exit();
        })
      });

      cryptofile.encode(INPUT_FILE, options, function(err) {
        if (err) {
          console.log('Encrypting file... Failed!');
          console.log(err);
        } else if (result) {
          console.log('Encrypting file... OK');
        
          if (result.encrypted_file_stat) {
            console.log('Encrypted file:', OUTPUT_FILE);
            console.log('Encrypted size:', bytes(result.encrypted_file_stat['size']));
          }
        }

        cryptofile.unload(function(err) {
          if (err) {
            console.log('Unload crypto file failed!');
            console.log(err);
          }
          process.exit();
        })
      });
    });
  });
} else if (command == 'decode') {
  if (argv.length < 1) {
    printUsage();
    process.exit();
  }

  var INPUT_FILE = path.resolve(argv[0]);
  if (!utils.fileExists(INPUT_FILE)) {
    console.log(chalk.red('Cryptofile not found:'), INPUT_FILE);
    process.exit();
  }
  console.log('Cryptofile: ' + INPUT_FILE);

  var default_output_dir = path.join(path.dirname(INPUT_FILE), path.basename(INPUT_FILE, path.extname(INPUT_FILE)));
  var OUTPUT_FILE = argv[1] ? path.resolve(argv[1]) : default_output_dir;

  if (!options.force && utils.fileExists(OUTPUT_FILE)) {
    console.log(chalk.red('File exists:'), OUTPUT_FILE);
    console.log(chalk.grey('Hint: Add --force or -f to replace existing file.'));
    process.exit();
  }
  console.log('Decode to: ' + OUTPUT_FILE);

  options.read_only = true;

  getEncryptionKey(function(err, enc_key) {
    if (err) {
      // console.log(err);
      console.log('');
      process.exit();
    }

    var cryptofile = new CryptoFile(INPUT_FILE, enc_key);

    if (options.progress) {
      options.onEntry = function(entry) {
        console.log((entry.type || 'File')[0], entry.path, chalk.magenta(bytes(entry.size)));
      }
    }

    cryptofile.load(function(err) {
      if (err) {
        console.log('Load crypto file failed!');
        // console.log(err);
        console.log(chalk.red(err.message));
        process.exit();
      }

      process.on('SIGINT', function() {
        console.log("\nCaught interrupt signal");
        cryptofile.unload(function(err) {
          if (err) {
            console.log('Unload crypto file failed!');
            console.log(err);
          }
          process.exit();
        })
      });

      cryptofile.decode(OUTPUT_FILE, options, function(err, result) {
        if (err) {
          console.log('Decrypting file... Failed!');
          console.log(err);
        } else if (result) {
          console.log('Decrypting file... OK');

          if (result.decrypted_file_stat) {
            console.log('Decrypted file:', OUTPUT_FILE);
            console.log('Decrypted size:', bytes(result.decrypted_file_stat['size']));
          }
        }

        cryptofile.unload(function(err) {
          if (err) {
            console.log('Unload crypto file failed!');
            console.log(err);
          }
          process.exit();
        })
      });
    });
  });
} else if (command == 'info') {
  if (argv.length < 1) {
    printUsage();
    process.exit();
  }

  var INPUT_FILE = path.resolve(argv[0]);
  if (!utils.fileExists(INPUT_FILE)) {
    console.log(chalk.red('Cryptofile not found:'), INPUT_FILE);
    process.exit();
  }
  console.log('Cryptofile: ' + INPUT_FILE);

  options.read_only = true;

  getEncryptionKey(function(err, enc_key) {
    if (err) {
      // console.log(err);
      console.log('');
      process.exit();
    }

    var cryptofile = new CryptoFile(INPUT_FILE, enc_key);

    cryptofile.load(function(err) {
      if (err) {
        console.log('Load crypto file failed!');
        // console.log(err);
        console.log(chalk.red(err.message));
        process.exit();
      }

      process.on('SIGINT', function() {
        console.log("\nCaught interrupt signal");
        cryptofile.unload(function(err) {
          if (err) {
            console.log('Unload crypto file failed!');
            console.log(err);
          }
          process.exit();
        })
      });

      cryptofile.info(options, function(err, result) {
        if (err) {
          console.log(err);
        } else if (result) {
          console.log(chalk.bold('File name:'), result.original_file.path);
          console.log(chalk.bold('File size:'), bytes(result.original_file.size));
          
          if (result.encrypted_file_stat) {
            console.log(chalk.bold('Encrypted size:'), bytes(result.encrypted_file_stat['size']));
          }
        }

        cryptofile.unload(function(err) {
          if (err) {
            console.log('Unload crypto file failed!');
            console.log(err);
          }
          process.exit();
        });
      });
    });
  });
} else {
  printUsage();
  process.exit();
}
