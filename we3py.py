from web3 import Web3
import json
from solc import compile_files,link_code,compile_source
from flask import Flask, Response, request, jsonify
from marshmallow import Schema, fields, ValidationError

# web3.py instance
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))

def deploy_contract(contract_interface):
    # Instantiate and deploy contract
    contract = w3.eth.contract(
        abi=contract_interface['abi'],
        bytecode=contract_interface['bin']
    )
    # Get transaction hash from deployed contract
    tx_hash = contract.deploy(
        transaction={'from': w3.eth.accounts[1]}
    )
    # Get tx receipt to get contract address
    tx_receipt = w3.eth.getTransactionReceipt(tx_hash)
    return tx_receipt['contractAddress']

# compile all contract files
contracts = compile_files(['user.sol', 'stringUtils.sol'])
main_contract = contracts.pop("user.sol:userRecords")
library_link = contracts.pop("stringUtils.sol:StringUtils")
# print bin part in  console you will see 'stringUtils' in that we need to link library address in that bin code.
# to that we have to deploy library code first then link it
library_address = {
    "stringUtils.sol:StringUtils": deploy_contract(library_link)
}

# separate main file and link file
main_contract['bin'] = link_code(
    main_contract['bin'],library_address
        )

def deploy_contract(contract_interface):
    contract = w3.eth.contract(
        abi = contract_interface['abi'],
        bytecode = contract_interface['bin']
    )
    tx_hash = contract.deploy(
        transaction={'from': w3.eth.accounts[1]}
    )
    # 获取tx收据以获取合同地址
    tx_receipt = w3.eth.getTransactionReceipt(tx_hash)
    return tx_receipt['contractAddress']

contract_address = deploy_contract(main_contract)

with open('data.json', 'w') as outfile:
    data = {
        "abi": main_contract['abi'],
        "contract_address": deploy_contract(main_contract)
    }
    json.dump(data, outfile, indent=4, sort_keys=True)

def check_gender(data):
    valid_list = ["male", "female"]
    if data not in valid_list:
        raise ValidationError(
            'Invalid gender. Valid choices are'+ valid_list
        )

    #For api validations
class UserSchema(Schema):
        name = fields.String(required=True)
        gender = fields.String(required=True, validate=check_gender)

#initializing falsk app
app = Flask(__name__)
app.debug=True

#api to set new user every api call
@app.route("/blockchain/user", methods=['POST'])
def user():
    body = request.get_json()
    result, error = UserSchema().load(body)
    if error:
        return jsonify(error), 422
    return jsonify({"data": result}), 200

if __name__ == "__main__":
    app.run()



