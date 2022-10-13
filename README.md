# btc-demo

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