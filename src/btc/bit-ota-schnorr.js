const bitcoin = require('bitcoinjs-lib')
const Client = require('bitcoin-core');
const crypto = require('crypto');
const ecpair = require('ecpair')

const trt = require('./lib/taproot-tools');

const network =bitcoin.networks.testnet;
const DEFAULT_SEQUENCE = 0xffffffff;

const jacobAddr ='mwVo1aPkstdovMQq7jBNuFRhKg9ikrTXiy';
const  jacobWifPrvKey='cNtRhd91x3uUvinJ8s4jSSUsTHGm4LbQ6Ck2a3XiYZLaq5NpiBHw';

const gpkStr = '04eba73b696713608526facf4fbe14b2ce110c1341e63bd00fe4ea5fe4b9e9b97c58bc218a11a3447c32243e57e7dad167d15c35ac2fb4e40979e97cc021a3ce45';

const  options = {
    network: 'testnet',
    host: "bitcoind-testnet.wandevs.org",
    port: 36893,
    username: 'wanglu',
    password: 'Wanchain888'
};
const rndId = '0x1234';
const wanAddress = '0x9da26fc2e1d6ad9fdd46138906b0104ae68a65d8';

function getHash(id, user) {
    console.log("getHash id = %s",id)
    console.log("getHash user = %s", user)
    if (!id.startsWith('0x')) {
        id = '0x' + id;
    }
    if (!user.startsWith('0x')) {
        user = '0x' + user;
    }
    const hash = crypto.createHash('sha256');
    hash.update(id + user);
    let ret = hash.digest('hex');
    console.log('getHash id = %s user=%s hash(id,user)', id, user, ret);
    if (ret.startsWith('0x')) {
        ret = ret.slice(2);
    }
    return ret;
}


// to v1Segwit
async function JacobToGpk(fromAddr, txId, utxoPreVout,network,toP2TrAddr,amount,client,fee=300){
    let tx = new bitcoin.Transaction()
    tx.version = 2

    let preOutScript = bitcoin.address.toOutputScript(fromAddr,network)
    tx.addInput(Buffer.from(txId, 'hex').reverse(), utxoPreVout);


    tx.addOutput(preOutScript, 1593601-fee-amount);     // index : 0

    //todo need to use the P2TR output script
    tx.addOutput(bitcoin.address.toOutputScript(toP2TrAddr,network), amount);               // index : 1

    let hash = tx.hashForSignature(0,preOutScript,1);

    const ecc = await import('tiny-secp256k1');
    // wrap the bip32 library
    const ECPair = ecpair.ECPairFactory(ecc)
    let ecPair = ECPair.fromWIF(jacobWifPrvKey,network)

    // get sig for hash.
    let sig = ecPair.sign(hash)
    console.log("sig",sig)

    let signature = bitcoin.script.signature.encode(sig,bitcoin.Transaction.SIGHASH_ALL)
    let inputSig = bitcoin.payments.p2pkh({pubkey:ecPair.publicKey,network:network,signature:signature}).input
    tx.setInputScript(0,inputSig)

    let txSerialized = tx.toHex();
    console.log("tx=",txSerialized)
    let ret = client.sendRawTransaction(txSerialized)
    return  ret
};


// script path
//
async function scriptPathSpend(wits,fromP2TrAddr, txId, vout,network,toP2PKHAddr,amount,client,leafHash,fee=300){
    let tx = new bitcoin.Transaction()
    tx.version = 2

    let preOutScript = bitcoin.address.toOutputScript(fromP2TrAddr,network)
    tx.addInput(Buffer.from(txId, 'hex').reverse(), vout);

    let pubScript = bitcoin.address.toOutputScript(toP2PKHAddr,network)
    tx.addOutput(pubScript, 3000-fee-amount);     // index : 0

    //hashForWitnessV1(inIndex, prevOutScripts, values, hashType, leafHash, annex)
    let hash = tx.hashForWitnessV1(
        0,
        [preOutScript],
        [3000],
        bitcoin.Transaction.SIGHASH_DEFAULT,
        leafHash)
    console.log("hash for script path spend  transaction",hash.toString('hex'))
    // get sig from gpk.......
    tx.setWitness(0,wits)
    let txSerialized = tx.toHex();
    console.log("tx=",txSerialized)
    let ret = client.sendRawTransaction(txSerialized)
    return  ret
};


async function main(){

    const client = new Client(options);

    // let ret = await client.getTransactionByHash('000a50c42c28b532fcd6790e4e8901c41dc08f7b6c6a53730ab7fd23966cf3be','bin')
    // console.log(ret)
    // process.exit(0)

    // 1. build p2trAddr
    await trt.init();
    let id = getHash(rndId,wanAddress);
    let script = trt.getRedeemScript(id,trt.getXBytes(gpkStr));

    let script_node = {
        leaf_version:"0xc0",
        script:script
    };
    console.log(script_node);
    console.log("redeemscript is ",script.toString('hex'))

    let o = trt.createScriptSpendOutput(trt.getXBytes(gpkStr),script_node);
    console.log(o.isEven);
    console.log(o.output);

    let p2trAddr = trt.getP2TRAddr(o.output,network);
    console.log(p2trAddr.toString('hex'));

    //2. jacob->p2tr   (script path p2tr address)

    //let preTx = "23e4d7df83575ae3f380f8f5f512a05ef16acf7a8cbeb5ad36627735345b3a40";
    let preTx = "000a50c42c28b532fcd6790e4e8901c41dc08f7b6c6a53730ab7fd23966cf3be";
    let utxoPreTx = 0;
    let sendAmount = 3000;
    let txHash;

    // txHash = await JacobToGpk(jacobAddr,preTx,utxoPreTx,network,p2trAddr,sendAmount,client);
    // console.log("txHash JacobToGpk(to script path)",txHash)

    //https://blockstream.info/testnet/tx/000a50c42c28b532fcd6790e4e8901c41dc08f7b6c6a53730ab7fd23966cf3be?expand


    //3. gpk->jacb   (script path spend)
    let leafHash = trt.taproot_tree_helper(script_node)
    let txId
    //txId = '000a50c42c28b532fcd6790e4e8901c41dc08f7b6c6a53730ab7fd23966cf3be'
    txId = '55bdb50bca1be68fdca6a3f463008bf1aa07954802857f9b20008adcbb1c14c1'
    let sendAmount1 = 2000;


    let sig
    //sig = Buffer.from("8477d0d61bd7630f94ce09ab7a1c3c4dde95caaca6a0084a2058d57262ba0bdc02b64c4854c9e1364a6763adbe6934c33ae4fc266c12be0ca7a338c5ca5b4eb5",'hex') //sig by gpk
    sig = Buffer.from("921350bfcd0798dd8a67a786a1cfa626fa91b15d96ae017994a93667bc693c39627201fa99a69d7d1e605bea6711a84fd5ddefe19d3b0614b34af275bfdcab98",'hex') //sig by gpk
    let wits = trt.buildWitness(sig,gpkStr,script_node.script,o.isEven)
    for(let i=0;i<wits.length;i++){
        console.log("witness[%d]",i, wits[i].toString('hex'))
    }
    txHash = await scriptPathSpend(wits,p2trAddr,txId,1,network,jacobAddr,sendAmount1,client,leafHash);
    console.log("txHash JacobToGpk(spend script path)",txHash)
}

main();

/*

to p2TR:

    output2
    https://blockstream.info/testnet/tx/55bdb50bca1be68fdca6a3f463008bf1aa07954802857f9b20008adcbb1c14c1?expand

p2TR spend:

    input1
    https://blockstream.info/testnet/tx/9897244254c55f76bb119dc08e66cb7ab12effccb5be26bb705f884fde713882?expand

 */

/*


jacob@ubuntu:~/wanchain/bitcoin-ota-demo$ node bit-ota-schnorr.js
getHash id = 0x1234
getHash user = 0x9da26fc2e1d6ad9fdd46138906b0104ae68a65d8
getHash id = 0x1234 user=0x9da26fc2e1d6ad9fdd46138906b0104ae68a65d8 hash(id,user) 667176726361a0496de325f84dd0aa7cbb632f258da88b4d616d6cbe27bd4356
>>>>>>getRedeemScript  xOnlyMpcPk is �;ig`�&��O���
A�;���_��|
>>>>>>getRedeemScript  id is 667176726361a0496de325f84dd0aa7cbb632f258da88b4d616d6cbe27bd4356
{
  leaf_version: '0xc0',
  script: <Buffer 20 66 71 76 72 63 61 a0 49 6d e3 25 f8 4d d0 aa 7c bb 63 2f 25 8d a8 8b 4d 61 6d 6c be 27 bd 43 56 75 76 a9 14 ce ff 2a e3 36 ec 26 fb 24 d0 dc e2 1a ... 9 more bytes>
}
redeemscript is  20667176726361a0496de325f84dd0aa7cbb632f258da88b4d616d6cbe27bd43567576a914ceff2ae336ec26fb24d0dce21a28af7f1155ff8588ac
hex(h) before taggedHash TapLeaf c03b20667176726361a0496de325f84dd0aa7cbb632f258da88b4d616d6cbe27bd43567576a914ceff2ae336ec26fb24d0dce21a28af7f1155ff8588ac
false
<Buffer 51 20 c3 8c fc 0d 42 48 a1 83 79 aa a4 0c 27 42 3a 70 fe b3 0d e9 3e 91 8d 7d 64 02 d1 b8 0e c7 ee ac>
WARNING: Sending to a future segwit version address can lead to loss of funds. End users MUST be warned carefully in the GUI and asked if they wish to proceed with caution. Wallets should verify the segwit version from the output of fromBech32, then decide when it is safe to use which version of segwit.
tb1pcwx0cr2zfzscx7d25sxzws36wrltxr0f86gc6ltyqtgmsrk8a6kqzr6vdg
hex(h) before taggedHash TapLeaf c03b20667176726361a0496de325f84dd0aa7cbb632f258da88b4d616d6cbe27bd43567576a914ceff2ae336ec26fb24d0dce21a28af7f1155ff8588ac
witness[0] 921350bfcd0798dd8a67a786a1cfa626fa91b15d96ae017994a93667bc693c39627201fa99a69d7d1e605bea6711a84fd5ddefe19d3b0614b34af275bfdcab98
witness[1] eba73b696713608526facf4fbe14b2ce110c1341e63bd00fe4ea5fe4b9e9b97c
witness[2] 20667176726361a0496de325f84dd0aa7cbb632f258da88b4d616d6cbe27bd43567576a914ceff2ae336ec26fb24d0dce21a28af7f1155ff8588ac
witness[3] c1eba73b696713608526facf4fbe14b2ce110c1341e63bd00fe4ea5fe4b9e9b97c
WARNING: Sending to a future segwit version address can lead to loss of funds. End users MUST be warned carefully in the GUI and asked if they wish to proceed with caution. Wallets should verify the segwit version from the output of fromBech32, then decide when it is safe to use which version of segwit.
hash for script path spend  transaction 7aac9ff1ae6db8a00cd93a51d71276fe19cc227e7b85f1d4045b4b0d7486fa40
tx= 02000000000101c1141cbbdc8a00209b7f8502489507aaf18b0063f4a3a6dc8fe61bca0bb5bd550100000000ffffffff01bc020000000000001976a914af49d8bb3ba52aff1b64346f24dff6d47653c01188ac0440921350bfcd0798dd8a67a786a1cfa626fa91b15d96ae017994a93667bc693c39627201fa99a69d7d1e605bea6711a84fd5ddefe19d3b0614b34af275bfdcab9820eba73b696713608526facf4fbe14b2ce110c1341e63bd00fe4ea5fe4b9e9b97c3b20667176726361a0496de325f84dd0aa7cbb632f258da88b4d616d6cbe27bd43567576a914ceff2ae336ec26fb24d0dce21a28af7f1155ff8588ac21c1eba73b696713608526facf4fbe14b2ce110c1341e63bd00fe4ea5fe4b9e9b97c00000000
txHash JacobToGpk(spend script path) 9897244254c55f76bb119dc08e66cb7ab12effccb5be26bb705f884fde713882


 */