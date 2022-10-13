const crypto = require('crypto');

// bitcoinjs-lib v6
const bitcoin = require('bitcoinjs-lib');

// bip32 v3 wraps tiny-secp256k1
const BIP32Wrapper = require('bip32').default;

const cuint = require('compact-uint');

let ecc,bip32;

// End imports


async function init(){
    // tiny-secp256k1 v2 is an ESM module, so we can't "require", and must import async
    ecc = await import('tiny-secp256k1');
    // wrap the bip32 library
    bip32 = BIP32Wrapper(ecc);
}

///////////////// key path spend begin /////////////////
// Function for creating signed tx
function createSigned(key, txid, vout, amountToSend, scriptPubkeys, values) {
    const tx = new bitcoin.Transaction();
    tx.version = 2;
    // Add input
    tx.addInput(Buffer.from(txid, 'hex').reverse(), vout);
    // Add output
    tx.addOutput(scriptPubkeys[0], amountToSend);
    const sighash = tx.hashForWitnessV1(
        0, // which input
        scriptPubkeys, // All previous outputs of all inputs
        values, // All previous values of all inputs
        bitcoin.Transaction.SIGHASH_DEFAULT // sighash flag, DEFAULT is schnorr-only (DEFAULT == ALL)
    );
    const signature = Buffer.from(signTweaked(sighash, key));
    // witness stack for keypath spend is just the signature.
    // If sighash is not SIGHASH_DEFAULT (ALL) then you must add 1 byte with sighash value
    tx.ins[0].witness = [signature];
    return tx;
}

// pk: hexString
// function createKeySpendOutput(pk) {
//     // x-only pubkey (remove 1 byte y parity)
//     const myXOnlyPubkey = pk.slice(1, 33);
//     const commitHash = bitcoin.crypto.taggedHash('TapTweak', myXOnlyPubkey);
//     const tweakResult = ecc.xOnlyPointAddTweak(myXOnlyPubkey, commitHash);
//     if (tweakResult === null) throw new Error('Invalid Tweak');
//     const {xOnlyPubkey: tweaked} = tweakResult;
//     // scriptPubkey
//     return Buffer.concat([
//         // witness v1, PUSH_DATA 32 bytes
//         Buffer.from([0x51, 0x20]),
//         // x-only tweaked pubkey
//         tweaked,
//     ]);
// }

////////////////// key path send end /////////////////


////////////////// script path spend begin /////////////////
// Function for creating signed tx
// for script s
function createScriptSigned(key, txid, vout, amountToSend, scriptPubkeys, values, inputIndex, signature, xOnlyPk) {
    const tx = new bitcoin.Transaction();
    tx.version = 2;
    // Add input
    tx.addInput(Buffer.from(txid, 'hex').reverse(), vout);
    // Add output
    tx.addOutput(scriptPubkeys[0], amountToSend);
    const sighash = tx.hashForWitnessV1(
        inputIndex, // which input
        scriptPubkeys, // All previous outputs of all inputs
        values, // All previous values of all inputs
        bitcoin.Transaction.SIGHASH_DEFAULT // sighash flag, DEFAULT is schnorr-only (DEFAULT == ALL)
    );
    // witness stack for keypath spend is just the signature.
    // If sighash is not SIGHASH_DEFAULT (ALL) then you must add 1 byte with sighash value

    let script, control;
    //todo build script and control (merkle script path c0+xOnlyPk+32*m)
    tx.ins[inputIndex].witness = [signature, xOnlyPk, script, control];
    return tx;
}

/*
in:
    isEven: true|false
    xOnlyPk: bytes
output: bytes
*/
function buildControlBlock(isEven, xOnlyPk) {
    if (isEven) {
        return Buffer.concat([
            Buffer.from("c0", 'hex'),
            xOnlyPk
        ])
    } else {
        return Buffer.concat([
            Buffer.from("c1", 'hex'),
            xOnlyPk
        ])
    }
}

// internalPubkey: gpk   32 bytes
// scriptTree:
/*
script_tree:{
    leaf_version:    // hexString  "0xc0"
    script:          // bytes
}

out:
{
    isEven: bool
    output: bytes
}
*/
function createScriptSpendOutput(internalPubkey, scriptTree) {
    // x-only pubkey (remove 1 byte y parity)
    //const myXOnlyPubkey = internalPubkey.slice(1, 33);

    const myXOnlyPubkey = internalPubkey;
    let h = taproot_tree_helper(scriptTree);
    const commitHash = bitcoin.crypto.taggedHash('TapTweak', Buffer.concat([myXOnlyPubkey, h]));
    const tweakResult = ecc.xOnlyPointAddTweak(myXOnlyPubkey, commitHash);
    if (tweakResult === null) throw new Error('Invalid Tweak');
    const {parity: par, xOnlyPubkey: tweaked} = tweakResult;
    // scriptPubkey
    return {
        isEven: !!!par,
        output: Buffer.concat([
            // witness v1, PUSH_DATA 32 bytes
            Buffer.from([0x51, 0x20]),
            // x-only tweaked pubkey
            tweaked,
        ])
    };
}

function removeHexPrefix(s){
    if(s.substring(0,2).toLowerCase() === '0x'){
        return s.substring(2)
    }
    return s
}

// return h
// only support one element root.
// todo support elements
function taproot_tree_helper(script_tree) {
    if (script_tree == null) {
        throw "empty tree"
    }
    if (script_tree.leaf_version.toString().toLowerCase() !== "0xc0") {
        throw "bad version"
    }
    //script buff
    let buf = Buffer.concat([
        Buffer.from(removeHexPrefix(script_tree.leaf_version.toString()), 'hex'),
        cuint.encode(script_tree.script.length),
        script_tree.script, // v || compact_size(size of s) || s

    ]);
    console.log("hex(h) before taggedHash TapLeaf", buf.toString('hex'))
    return bitcoin.crypto.taggedHash('TapLeaf', buf);
}

///////////////// script path spend end /////////////////


///////////////// common function for both begin /////////////////

// Function for signing for a tweaked p2tr key-spend only address
// (Required for the above address)
function signTweaked(messageHash, key) {
    const privateKey =
        key.publicKey[0] === 2
            ? key.privateKey
            : ecc.privateAdd(ecc.privateSub(N_LESS_1, key.privateKey), ONE);
    const tweakHash = bitcoin.crypto.taggedHash(
        'TapTweak',
        key.publicKey.slice(1, 33)
    );
    const newPrivateKey = ecc.privateAdd(privateKey, tweakHash);
    if (newPrivateKey === null) throw new Error('Invalid Tweak');
    return ecc.signSchnorr(messageHash, newPrivateKey, Buffer.alloc(32));
}

function getSigHash(txid, vout, amountToSend, scriptPubkeys, values, inputIndex) {
    const tx = new bitcoin.Transaction();
    tx.version = 2;
    // Add input
    tx.addInput(Buffer.from(txid, 'hex').reverse(), vout);
    // Add output
    tx.addOutput(scriptPubkeys[0], amountToSend);
    const sighash = tx.hashForWitnessV1(
        inputIndex, // which input
        scriptPubkeys, // All previous outputs of all inputs
        values, // All previous values of all inputs
        bitcoin.Transaction.SIGHASH_DEFAULT // sighash flag, DEFAULT is schnorr-only (DEFAULT == ALL)
    );
    return sighash
}

/*
 step1:  getRedeemScript， 得到一次性脚本
 step2:  createScriptSpendOutput, 根据脚本和gpk得到锁定脚本
 step3:  getP2TRAddr,根据锁定脚本得到p2tr地址
 */

function getP2TRAddr(scriptOut, network) {
    return bitcoin.address.fromOutputScript(
        scriptOut,
        network
    );
}

///////////////// common funciton for both end/////////////////

//in: xOnlyMpcPk   32bytes
function getRedeemScript(id, xOnlyMpcPk) {
    console.log(">>>>>>getRedeemScript  xOnlyMpcPk is %s", xOnlyMpcPk);
    console.log(">>>>>>getRedeemScript  id is %s", id);
    return bitcoin.script.fromASM(
        `
    ${id}
    OP_DROP
    OP_DUP
    OP_HASH160
    ${bitcoin.crypto.hash160(Buffer.from(xOnlyMpcPk, 'hex')).toString('hex')}
    OP_EQUALVERIFY
    OP_CHECKSIG
    `.trim()
            .replace(/\s+/g, ' '),
    )
}

//in: xOnlyMpcPk   32bytes
function getRedeemScriptNoSig(id) {
    console.log(">>>>>>getRedeemScript  id is %s", id);
    return bitcoin.script.fromASM(
        `
    ${id}
    OP_DROP    
    `.trim()
            .replace(/\s+/g, ' '),
    )
}

function getTrue() {
    return bitcoin.script.fromASM(
        `
    OP_TRUE        
    `.trim()
            .replace(/\s+/g, ' '),
    )
}


function getGpkRedeemScript(xOnlyMpcPk) {
    console.log(">>>>>>getGpkRedeemScript  MPC_PK is %s", xOnlyMpcPk);
    return bitcoin.script.fromASM(
        `
    OP_DUP
    OP_HASH160
    ${bitcoin.crypto.hash160(Buffer.from(xOnlyMpcPk, 'hex')).toString('hex')}
    OP_EQUALVERIFY
    OP_CHECKSIG
    `.trim()
            .replace(/\s+/g, ' '),
    )
}

// in: hexString
// out: byte
function  getXBytes(pk){
    let pkTemp = pk;
    if(pk.slice(0,2).toString().toLowerCase() === "0x"){
        pkTemp = pk.slice(2)
    }
    if(pkTemp.length == 64){
        return Buffer.from(pkTemp.slice(0,64),'hex')
    }
    if(pkTemp.length == 66){
        return Buffer.from(pkTemp.slice(2,66),'hex')
    }
    if(pkTemp.length == 128){
        return Buffer.from(pkTemp.slice(0,64),'hex')
    }
    if(pkTemp.length == 130){
        return Buffer.from(pkTemp.slice(2,66),'hex')
    }
    return "";
}

// signature:buff
// gpk: hexString
// script: buff
// controlBlock: buff
// output: []Buff
function buildWitness(signature,gpk,script,isEven){
    let xOnlyPk = getXBytes(gpk)
    let c = buildControlBlock(isEven,xOnlyPk)
    return [signature,xOnlyPk,script,c]
}
// pk: hexString
function buildWitnessNoSig(pk,script,isEven){
    let xOnlyPk = getXBytes(pk)
    let c = buildControlBlock(isEven,xOnlyPk)
    return [Buffer.from("01",'hex'),script,c]
}

// return: hexString PK
async function genPk(network){
    const bip39 = require('bip39');
    const ecc = await import('tiny-secp256k1');
    const bip32 = BIP32Wrapper(ecc);
    let words = bip39.generateMnemonic(256);
    console.log(words);
    console.log('is valid mnemonic? ' + bip39.validateMnemonic(words));

    let seed = bip39.mnemonicToSeedSync(words)
    const root = bip32.fromSeed(seed, network);
    const myKey = root.derivePath("m/44'/0'/0'/0/0");
    let myacc = bitcoin.payments.p2pkh({pubkey: myKey.publicKey, network:network})
    let myaddress = myacc.address
    console.log("mypkhaddr:", myaddress)
    console.log("publicKey",myKey.publicKey)
    return myKey.publicKey.toString('hex')
}

module.exports = {
    //createKeySpendOutput: createKeySpendOutput,
    createScriptSpendOutput: createScriptSpendOutput,
    getP2TRAddr: getP2TRAddr,
    createScriptSigned: createScriptSigned,
    getSigHash: getSigHash,
    getGpkRedeemScript: getGpkRedeemScript,
    getRedeemScript: getRedeemScript,
    getXBytes:getXBytes,
    init:init,
    buildControlBlock:buildControlBlock,
    taproot_tree_helper:taproot_tree_helper,
    buildWitness:buildWitness,
    buildWitnessNoSig:buildWitnessNoSig,
    getRedeemScriptNoSig:getRedeemScriptNoSig,
    genPk:genPk,

};

/*
///////////////////////////////////////////////////////
quesiton form Jacob

1. If q ≠ x(Q) or c[0] & 1 ≠ y(Q) mod 2

1.1 c[0]的前面位数表示leaf_version, c[0] & 0xFE,  leaf_version怎么填写？？
1.2 c[0]的最后一位表示的是Q的Y坐标的奇偶，c[0] & 1
1.3 c[0]除了最后一位，别的位到底怎么填写？？

2. script spend中的签名验证，签名的对象的hash是不是和key spend不一样？

3.  varientUint   bip174/src/lib/converter/varint

*/