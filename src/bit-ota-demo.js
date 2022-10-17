const bitcoin = require('bitcoinjs-lib5')
const Client = require('bitcoin-core');
const crypto = require('crypto');

const network =bitcoin.networks.testnet;
const DEFAULT_SEQUENCE = 0xffffffff;
const SignAll = 1;

const jacobAddr ='mwVo1aPkstdovMQq7jBNuFRhKg9ikrTXiy';
const  jacobWifPrvKey='cNtRhd91x3uUvinJ8s4jSSUsTHGm4LbQ6Ck2a3XiYZLaq5NpiBHw';

const gpkStr = '04b332e3519e3fa5acff123c9faf94054c3929a32be331698d680e43e8a38aeb0527a6ddcc8f1b635a52870ad73fcc89ac87abab5ffcdb3bdef021a376adbb03d6';
const gpkAddr = 'mqG5idxDaMFmEiVSaqK11HAkA2PegRSiF8';

const  btcServerNet = {
    network: 'testnet',
    host: "52.40.34.234",
    port: 36893,
    username: 'wanglu',
    password: 'Wanchain888'
};
const sigsHexStr =  ["0x304402204c1689aac3a16929edd0f1d3b5eae574026b038d85279f1a9d540c30b55238d402206428c4be1029f4e524cc24b31347f265ca00f528b41adf95fdfabac60ff7969901", "0x30440220222329ac7b88d056b1d586c531077620f864c522f803c7e5b44b479c25cf90c702203a2a2e7d5d1c954a451f98dce3e32e44ba4b74baefe2661823e60961db52991a01"]

const toGpkP2pkhValue = 105000;
const toGpkP2shValue =   45000;


const toJacobP2pkhValue = 145000;
const toJacobP2shValue  = 0;


const rndId = '0x1234';
const wanAddress = '0x9da26fc2e1d6ad9fdd46138906b0104ae68a65d8';
// total :155000

const jacobUtxoPreTx = '771fdc6510769e45884bc7f39afdb21f90f987001d6d7f2ba92ab5b58cdfbf57';

function getRedeemScript(id, MPC_PK) {
    console.log(">>>>>>getRedeemScript  MPC_PK is %s",MPC_PK);
    console.log(">>>>>>getRedeemScript  id is %s",id);
    return bitcoin.script.fromASM(
        `
    ${id}
    OP_DROP
    OP_DUP
    OP_HASH160
    ${bitcoin.crypto.hash160(Buffer.from(MPC_PK, 'hex')).toString('hex')}
    OP_EQUALVERIFY
    OP_CHECKSIG
    `.trim()
            .replace(/\s+/g, ' '),
    )
}

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

function getP2SHAddr(id, NETWORK, MPC_PK) {
    console.log(">>>>>>>>getP2SHAddr ret of getRedeemScript is %s",getRedeemScript(id, MPC_PK).toString('hex'))
    const p2sh = bitcoin.payments.p2sh({
        network: NETWORK,
        redeem: {
            output: getRedeemScript(id, MPC_PK),
            network: NETWORK
        },
    });
    return p2sh.address;
}

async function sendTrans(rawTx){
    let client = new Client(btcServerNet);
    let txHash = await client.sendRawTransaction(rawTx)
    return txHash
}


//  in: jacob's utxo
//  out1: p2pkh of gpk
//  out2: p2sh  of gpk
async function JacobToGpk(){
    let id = getHash(rndId,wanAddress)
    let gpkShAddr = getP2SHAddr(id,network,gpkStr)

    let txb = new bitcoin.TransactionBuilder(network);
    txb.setVersion(1)
    let preOutScript = bitcoin.address.toOutputScript(jacobAddr,network)
    txb.addInput(jacobUtxoPreTx, 0,DEFAULT_SEQUENCE,preOutScript);

    txb.addOutput(gpkShAddr, toGpkP2pkhValue);  // index : 0
    txb.addOutput(gpkAddr, toGpkP2shValue);     // index : 1

    let inIndex = 0

    let keyPair = bitcoin.ECPair.fromWIF(jacobWifPrvKey,network)
    txb.sign(inIndex,keyPair,null,SignAll)

    let tx = txb.build()
    let txSerialized = tx.toHex();
    console.log("tx=",txSerialized)
    return  txSerialized
};

// in1:  p2pkh of gpk
// in2:  p2sh of gpk
// out1: p2pkh of gpk
async function RedeempGpk(jacobUtxoPreTx1){
    let id = getHash(rndId,wanAddress);
    let gpkShAddr = getP2SHAddr(id,network,gpkStr);

    console.log("gpkShAddr is :%s",gpkShAddr);

    let txb = new bitcoin.TransactionBuilder(network);
    txb.setVersion(1);

    let preOutScriptP2sh = getRedeemScript(id,gpkStr);
    txb.addInput(jacobUtxoPreTx1, 0,DEFAULT_SEQUENCE,preOutScriptP2sh);

    let preOutScript = bitcoin.address.toOutputScript(gpkAddr,network);
    txb.addInput(jacobUtxoPreTx1, 1,DEFAULT_SEQUENCE,preOutScript);

    txb.addOutput(jacobAddr, Number(toJacobP2pkhValue)+Number(toJacobP2shValue));

    const tx = txb.buildIncomplete();

    let sigHash1 = tx.hashForSignature(0,preOutScriptP2sh,1);
    console.log("\n@@@@@@@@@@@@@sigHash1[p2sh] is ",sigHash1.toString('hex'));

    const redeemScriptSig = bitcoin.payments.p2sh({
        redeem: {
            input: bitcoin.script.compile([
                Buffer.from(sigsHexStr[0].substr(2), 'hex'),
                Buffer.from(gpkStr, 'hex'),
            ]),
            //output: redeemScript,
            output: preOutScriptP2sh,
            network:bitcoin.networks.testnet,
        },
    }).input;

    tx.setInputScript(0, redeemScriptSig);

    let sigHash = tx.hashForSignature(1,preOutScript,1);
    console.log("\n@@@@@@@@@@@@@sigHash[p2pk] is ",sigHash.toString('hex'));

    let scriptSig = bitcoin.script.compile([Buffer.from(sigsHexStr[1].substr(2),'hex'),Buffer.from(gpkStr,'hex')])
    tx.setInputScript(1, scriptSig);

    console.log("scriptSig is :",scriptSig);
    console.log("txSerialized1 is ",tx.toHex());
    return tx.toHex();
};



async function buildMpcJson(jacobUtxoPreTx1){
    let id = getHash(rndId,wanAddress);
    let gpkShAddr = getP2SHAddr(id,network,gpkStr);

    let inPut1Script = getRedeemScript(id,gpkStr);
    let inPut2Script = bitcoin.address.toOutputScript(gpkAddr,network);

    let outPut1Script = bitcoin.address.toOutputScript(jacobAddr,network);

    let mpcJson = {
        "Version": 1,
        "LockTime": 0,
        "From": "0xb332e3519e3fa5acff123c9faf94054c3929a32be331698d680e43e8a38aeb0527a6ddcc8f1b635a52870ad73fcc89ac87abab5ffcdb3bdef021a376adbb03d6",
        "TxIn": [{
        "PreviousOutPoint": {
            "Hash": "e778c05b879e577ee24058c944a632433e6fac41a8ff96e6ea9bf6ffb6a0dbd0",
            "Index": 0
        },
        "SignatureScript": "0x76a9142436df0553c3f94395bd4bb1954d69067985c45088ac",
        "Sequence": 4294967295,
        "PkScript": ""
    },{
        "PreviousOutPoint": {
            "Hash": "e778c05b879e577ee24058c944a632433e6fac41a8ff96e6ea9bf6ffb6a0dbd0",
            "Index": 1
        },
        "SignatureScript": "0x76a9142436df0553c3f94395bd4bb1954d69067985c45088ac",
        "Sequence": 4294967295,
        "PkScript": ""
    }],
        "TxOut": [{
        "PkScript": "0x76a9142436df0553c3f94395bd4bb1954d69067985c45088ac",
        "Value": 97400
    }]
    }

    mpcJson.TxIn[0].SignatureScript = "0x"+ inPut1Script.toString('hex');
    mpcJson.TxIn[1].SignatureScript = "0x"+ inPut2Script.toString('hex');
    mpcJson.TxOut[0].PkScript = "0x"+ outPut1Script.toString('hex');
    mpcJson.TxOut[0].Value = 145000;

    console.log("TxIn0 sigScipt",mpcJson.TxIn[0].SignatureScript);
    console.log("TxIn1 sigScipt",mpcJson.TxIn[1].SignatureScript);

    mpcJson.TxIn[0].PreviousOutPoint.Hash = reviseHash(jacobUtxoPreTx1);
    mpcJson.TxIn[1].PreviousOutPoint.Hash = reviseHash(jacobUtxoPreTx1);

    console.log("mpcJson",JSON.stringify(mpcJson))
}


function reverseBuffer(buffer) {
    if (buffer.length < 1) return buffer;
    let j = buffer.length - 1;
    let tmp = 0;
    for (let i = 0; i < buffer.length / 2; i++) {
        tmp = buffer[i];
        buffer[i] = buffer[j];
        buffer[j] = tmp;
        j--;
    }
    return buffer;
}

function reviseHash(txHash){
    let buf = Buffer.from(txHash,'hex')
    let buf1 = reverseBuffer(buf)
    return buf1.toString('hex')
}

async function main(){
    // in :150000
    // out1: 105000
    // out2:  45000
    console.log("*********************************Jacob to gpk (p2pk and p2sh)*******************************************");
    let  rawTx = await JacobToGpk()

    // let retHash = await sendTrans(rawTx)
    // console.log("retHash=%s",retHash)

    // 成功上链 txHash = e778c05b879e577ee24058c944a632433e6fac41a8ff96e6ea9bf6ffb6a0dbd0
    /*
    raw tran:
    010000000157bfdf8cb5b52aa92b7f6d1d0087f9901fb2fd9af3c74b88459e761065dc1f77000000006a47304402203786291358b4c60997922fbcc8d6d7348a55658cc6d97bb9bfa2a864f8ca099f022061ad649dc429832b2365d6e439e6d9deca4d62fb33d2212cd00d15e4fc68d56f012103c734e31969094b23a14843e0cac012025ceaf46635204d5d5ca80645b5c12967ffffffff02289a01000000000017a914eb90b97825108aa9232323de8abc088de7d30cc287c8af0000000000001976a9146ae1372d767dba6e0b0350b4ed28045273eebfc988ac00000000
     */
    let  txHash = 'e778c05b879e577ee24058c944a632433e6fac41a8ff96e6ea9bf6ffb6a0dbd0';
    /*

     */
    console.log("********************************build mpc json********************************************");
    await buildMpcJson(txHash);
    console.log("********************************gpk(p2pk and p2sh) to jacob********************************************");

    // get signature form mpc
    // change siganture hex string

    // 成功上链 txHash = 35f62fa74a4d7baaaaca35cc7bcff201a439d5f3de2dca1bbb0f7ca2b68c23eb
    let rawTx1 = await RedeempGpk(txHash);
    // let retHash1 = await sendTrans(rawTx1);
    // console.log("retHash1=%s",retHash1);
    console.log("****************************************************************************");
}
main()


/*
上链成功的json 给MPC


{
	"Version": 1,
	"LockTime": 0,
	"From": "0xb332e3519e3fa5acff123c9faf94054c3929a32be331698d680e43e8a38aeb0527a6ddcc8f1b635a52870ad73fcc89ac87abab5ffcdb3bdef021a376adbb03d6",
	"TxIn": [{
		"PreviousOutPoint": {
			"Hash": "e778c05b879e577ee24058c944a632433e6fac41a8ff96e6ea9bf6ffb6a0dbd0",
			"Index": 0
		},
		"SignatureScript": "0x20667176726361a0496de325f84dd0aa7cbb632f258da88b4d616d6cbe27bd43567576a9146ae1372d767dba6e0b0350b4ed28045273eebfc988ac",
		"Sequence": 4294967295,
		"PkScript": ""
	}, {
		"PreviousOutPoint": {
			"Hash": "e778c05b879e577ee24058c944a632433e6fac41a8ff96e6ea9bf6ffb6a0dbd0",
			"Index": 1
		},
		"SignatureScript": "0x76a9146ae1372d767dba6e0b0350b4ed28045273eebfc988ac",
		"Sequence": 4294967295,
		"PkScript": ""
	}],
	"TxOut": [{
		"PkScript": "0x76a914af49d8bb3ba52aff1b64346f24dff6d47653c01188ac",
		"Value": 145000
	}]
}

 */


/*
mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)

用p2sh的签名消费p2pkh的utxo.

 */