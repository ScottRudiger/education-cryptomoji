'use strict';

const { createHash } = require('crypto');
const { verify } = require('./signing');
const { Block, sha512, getSignatures } = require('./blockchain');

/**
 * A simple validation function for transactions. Accepts a transaction
 * and returns true or false. It should reject transactions that:
 *   - have negative amounts
 *   - were improperly signed
 *   - have been modified since signing
 */
const isValidTransaction = ({source, recipient, amount, signature}) => verify(
  source,
  source + recipient + amount,
  signature,
) && amount >= 0;

/**
 * Validation function for blocks. Accepts a block and returns true or false.
 * It should reject blocks if:
 *   - their hash or any other properties were altered
 *   - they contain any invalid transactions
 */
const isValidBlock = ({transactions: txs, nonce, hash, previousHash}) =>
  txs.every(isValidTransaction)
  && hash === sha512(previousHash + getSignatures(txs) + nonce);


/**
 * One more validation function. Accepts a blockchain, and returns true
 * or false. It should reject any blockchain that:
 *   - is missing a genesis block
 *   - has any block besides genesis with a null hash
 *   - has any block besides genesis with a previousHash that does not match
 *     the previous hash
 *   - contains any invalid blocks
 *   - contains any invalid transactions
 */
const isValidChain = ({blocks: [genesis, ...blocks]}) => blocks.every(isValidBlock)
  && genesis.previousHash === null
  && blocks.every(({previousHash}, i) => previousHash === [genesis, ...blocks][i].hash);

/**
 * This last one is just for fun. Become a hacker and tamper with the passed in
 * blockchain, mutating it for your own nefarious purposes. This should
 * (in theory) make the blockchain fail later validation checks;
 */
const breakChain = ({blocks: [genesis]}) => genesis.previousHash = 0;

module.exports = {
  isValidTransaction,
  isValidBlock,
  isValidChain,
  breakChain
};
