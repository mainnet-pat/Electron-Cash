##!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Electron Cash - A Bitcoin Cash SPV Wallet
# This file Copyright (c) 2022 mainnet_pat
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

'''
Minimal web3 client implementation and LNS smart contract interaction
'''
import json
import time
from electroncash.contrib.eth_abi import decode_abi, encode_abi
from electroncash.contrib.eth_utils import add_0x_prefix, encode_hex, function_abi_to_4byte_selector, to_bytes, to_hex
from electroncash.contrib.eth_utils.abi import collapse_if_tuple

from hexbytes import HexBytes
import requests
from typing import Any, Dict, List, Union, cast

from electroncash.simple_config import get_config

abi = [
    {
      "inputs": [
        {
          "internalType": "contract ENS",
          "name": "_ens",
          "type": "address"
        }
      ],
      "stateMutability": "nonpayable",
      "type": "constructor"
    },
    {
      "inputs": [
        {
          "internalType": "string[]",
          "name": "names",
          "type": "string[]"
        },
        {
          "internalType": "uint256",
          "name": "coinType",
          "type": "uint256"
        }
      ],
      "name": "getAddrs",
      "outputs": [
        {
          "internalType": "bytes[]",
          "name": "r",
          "type": "bytes[]"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address[]",
          "name": "addresses",
          "type": "address[]"
        }
      ],
      "name": "getNames",
      "outputs": [
        {
          "internalType": "string[]",
          "name": "r",
          "type": "string[]"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    }
  ]

rpc_servers = [
    "https://smartbch.fountainhead.cash/mainnet",
    "https://smartbch.greyh.at",
    "https://smartbch.electroncash.de",
    "https://global.uat.cash",
    "https://rpc.uatvo.com",
    "https://moeing.tech:9545",
    "http://localhost:8545"
]

graph_servers = [
    "https://graph.bch.domains/subgraphs/name/graphprotocol/ens",
    "https://graph.bch.domains/subgraphs/name/graphprotocol/ens-amber"
]

CONTRACT_ADDRESS = "0x0efB8EE0F6d6ba04F26101683F062d7Ca6F58A40"

def get_registrations(name: Union[str, List[str]], server, skip, batch, timeout=60.0) -> List[Dict]:
    '''
    Make a call to The Graph instance which have indexed the LNS registrations data
    '''
    now = int(time.time())

    def get_json(skip):
        if isinstance(name, list) or isinstance(name, set):
            names = [(str.split(n.strip(), '.bch')[0]).lower() for n in name]
            return {"query": f'{{registrations(first:{batch},skip:{skip},where:{{labelName_in:{json.dumps(names)},expiryDate_gt:"{now}"}}){{labelName,registrationDate,expiryDate}}}}'}
        else:
            lookupName = (str.split(name.strip(), '.bch')[0]).lower()
            return {"query": f'{{registrations(first:{batch},skip:{skip},where:{{labelName_contains:"{lookupName}",expiryDate_gt:"{now}"}}){{labelName,registrationDate,expiryDate}}}}'}

    r = requests.post(server, json=get_json(skip), allow_redirects=True, timeout=timeout) # will raise requests.exceptions.Timeout on timeout
    r.raise_for_status()
    d = r.json()
    if not isinstance(d, dict) or not d.get('data'):
        raise RuntimeError('Unexpected response', r.text)
    res = d['data']
    registrations = res['registrations']
    if not isinstance(registrations, list):
        raise RuntimeError('Bad response')

    return registrations


def get_addrs(names: List[str], timeout=60.0) -> List[bytes]:
    '''
    Make a call to LNS Helper web3 contract
    Minimal implementation of an web3 client
    '''

    def get_abi_input_types(abi: any) -> List[str]:
        if 'inputs' not in abi and (abi['type'] == 'fallback' or abi['type'] == 'receive'):
            return []
        else:
            return [collapse_if_tuple(cast(Dict[str, Any], arg)) for arg in abi['inputs']]

    def get_abi_output_types(abi: any) -> List[str]:
        if abi['type'] == 'fallback':
            return []
        else:
            return [collapse_if_tuple(cast(Dict[str, Any], arg)) for arg in abi['outputs']]

    def json_rpc_data(calldata):
        return {
            "jsonrpc":"2.0",
            "method":"eth_call",
            "params":[{
                "to": CONTRACT_ADDRESS,
                "data": calldata
            }, "latest"],
            "id":1
        }

    COIN_TYPE_BCH = 145
    rpc_server: str = get_config().get('lns_rpc_server', rpc_servers[0])
    abiFunction = abi[1]

    fn_selector = encode_hex(function_abi_to_4byte_selector(abiFunction))

    argument_types = get_abi_input_types(abiFunction)
    encoded_arguments = encode_abi(
        argument_types,
        [names, COIN_TYPE_BCH],
    )
    data = add_0x_prefix(to_hex(HexBytes(fn_selector) + encoded_arguments))

    r = requests.post(rpc_server, json=json_rpc_data(data), allow_redirects=True, timeout=timeout) # will raise requests.exceptions.Timeout on timeout
    return_data = r.json()

    output_types = get_abi_output_types(abiFunction)
    if not isinstance(return_data, dict) or not return_data.get('result'):
        raise RuntimeError('Unexpected response', r.text)
    output_data = decode_abi(output_types, to_bytes(None, return_data['result']))

    addrs = output_data[0]

    return addrs
