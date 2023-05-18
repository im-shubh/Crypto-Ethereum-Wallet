const {
  generateMnemonic,
  mnemonicToEntropy,
} = require("ethereum-cryptography/bip39");
const { wordlist } = require("ethereum-cryptography/bip39/wordlists/english");
const { HDKey } = require("ethereum-cryptography/hdkey");
const { getPublicKey } = require("ethereum-cryptography/secp256k1");
const keccak256 = require("js-sha3").keccak256;
const EC = require("elliptic").ec;
const { writeFileSync } = require("fs");

// Generate Mnemonic and Entropy using BIP39
function _generateMnemonic() {
  const strength = 128; // 256 bits, 24 words; default is 128 bits, 12 words

  // Generating  Mnemonic
  const mnemonic = generateMnemonic(wordlist, strength);

  // Converting   Mnemonic to Entropy
  const entropy = mnemonicToEntropy(mnemonic, wordlist);
  return { mnemonic, entropy };
}

// Generating Hierarchical deterministic (HD) key
function _getHdRootKey(_mnemonic) {
  return HDKey.fromMasterSeed(_mnemonic);
}

function _generatePrivateKey(_hdRootKey, _accountIndex) {
  return _hdRootKey.deriveChild(_accountIndex).privateKey;
}

function _getPublicKey(_privateKey) {
  return getPublicKey(_privateKey);
}

function _getEthAddress(_publicKey) {
  const ec = new EC("secp256k1");
  const key = ec.keyFromPublic(_publicKey, "hex");
  const publicKey = key.getPublic().encode("hex").slice(2);
  return keccak256(Buffer.from(publicKey, "hex")).slice(64 - 40);
}

function _store(_privateKey, _publicKey, _address, _mnemonic) {
  const accountOne = {
    privateKey: _privateKey,
    publicKey: _publicKey,
    address: _address,
    mnemonic: _mnemonic,
  };
  const accountOneData = JSON.stringify(accountOne);
  writeFileSync("account.json", accountOneData);
}

async function main() {
  const { mnemonic, entropy } = _generateMnemonic();
  console.log(`WARNING! Never disclose your Seed Phrase:\n ${mnemonic}`);

  const hdRootKey = _getHdRootKey(entropy);

  const accountOneIndex = 0;

  const accountOnePrivateKey = _generatePrivateKey(hdRootKey, accountOneIndex);

  const accountOnePublicKey = _getPublicKey(accountOnePrivateKey);

  const accountOneAddress = _getEthAddress(accountOnePublicKey);

  console.log(`You Ethereum Address:\n 0x${accountOneAddress}`);


  _store(
    accountOnePrivateKey,
    accountOnePublicKey,
    accountOneAddress,
    mnemonic
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
