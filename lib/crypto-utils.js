
var prompt = require('prompt');
var chalk = require('chalk');

var utils = require('./utils');

exports.generateEncryptionKey = function(passphrase, salt) {
  return utils.sha512Hash(passphrase, salt);
}

exports.getPromptPassphrase = function(options, callback) {
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

exports.getPromptSalt = function(options, callback) {
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
