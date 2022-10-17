# btc-demo

# 0. 搭建

~/.bitcoin/bitcoin.conf
-conf=相对于datadir的目录
-dadadir=data/btc-reg

## 告知 Bitcoin-QT 接受 JSON-RPC 命令
server=1

## 开启回归测试模式
regtest=1


[regtest]

## 开启交易记录索引
txindex=1

## 开启挖矿
gen=1

开启rpc端口
default: 8333
testnet: 18333
signet: 38333
regtest: 18444


# 1. node, mocha, 需要设置 type:module, 才能支持import语法

## package.json, add 

"type": "module",

# 2. ts-node, package.json, 需要移除 type:module, 才支持ts
## package.json, remove

"type": "module",

# 3. ts-mocha,, package.json, type:module 无影响
## remember to install mocha if you don't have it already (npm i -D mocha)

npm i -D ts-mocha

## install recent Mocha and Expect @types packages for best DX

npm i -D @types/mocha @types/expect

## package.json, add

"type": "module",


# 4. node --loader=ts-node/esm, type:module是否存在无影响

# 5. 结论, 
js里有 import时, package.json 中加 "type": "module",
ts时, 用ts-mocha 和 node --loader=ts-node/esm