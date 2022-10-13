const bitcoin = require('bitcoinjs-lib')
const Client = require('bitcoin-core');
const crypto = require('crypto');
const ecpair = require('ecpair')
const trt = require('./lib/taproot-tools');
const network =bitcoin.networks;

async function getAccount(){
    pkHex = '04a981b552688d64f4a17577b86f2b83805715a58c24e87a71082d442a6740049a1b1049209b0796569e27ca76dc0ae1fad6ed0e222d5fd7a53beef762d5b0b711'
    const ecc = await import('tiny-secp256k1');
    // wrap the bip32 library
    const ECPair = ecpair.ECPairFactory(ecc)
    let ecPair = ECPair.fromPublicKey(Buffer.from(pkHex,'hex'),{compressed:false})
    console.log("ecPair",ecPair)
    console.log("publicKey",ecPair.publicKey)

    let myacc = bitcoin.payments.p2pkh({pubkey:ecPair.publicKey, network:network.bitcoin})
    console.log(myacc.address)
}

getAccount()