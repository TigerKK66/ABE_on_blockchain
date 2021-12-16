from web3 import Web3, HTTPProvider

true = True
false = False
true = True
false = False
config = {
    "abi":[ # contract ABI
    {
        "constant": false,
        "inputs": [],
        "name": "callme",
        "outputs": [],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [],
        "name": "isComplete",
        "outputs": [
            {
                "name": "",
                "type": "bool"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    }
    ],
    "address":"0x35***27" # 合约地址
}

INFURA_api = "https://ropsten.infura.io/***" # INFURA's ropsten API address

web3 = Web3(HTTPProvider(INFURA_api))
contract_instance = web3.eth.contract(address=config['address'], abi=config['abi'])

my_addr = "0x97***1d" # account address
priv_key = "0xb***c" # account private key

def SendTxn(txn):
    signed_txn = web3.eth.account.signTransaction(txn,private_key=priv_key)
    res  = web3.eth.sendRawTransaction(signed_txn.rawTransaction).hex()
    txn_receipt = web3.eth.waitForTransactionReceipt(res)

    print(res)
    return txn_receipt

txn = contract_instance.functions.callme().buildTransaction(
    {
        'chainId':3,
        'nonce':web3.eth.getTransactionCount(my_addr),
        'gas':7600000,
        'value':Web3.toWei(0,'ether'),
        'gasPrice':web3.eth.gasPrice,
    }
)

print(SendTxn(txn))