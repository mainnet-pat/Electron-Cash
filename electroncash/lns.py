##!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Electron Cash - A Bitcoin Cash SPV Wallet
# This file Copyright (c) 2019 Calin Culianu <calin.culianu@gmail.com>
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
LNS related classes and functions.

# Note that this file also contains a unique class called `ScriptOutput` (which
# inherits from address.py's own ScriptOutput), so always import this file
# carefully if also importing address.py.
'''
from PyQt5.QtCore import QTimer

import json
import re
from sqlite3 import Date
from numpy import isin
import requests
import threading
import queue
import random
import time
from collections import defaultdict, namedtuple
from typing import List, Tuple, Dict, Union
from . import util
from .address import Address, Base58, OpCodes, Script, ScriptError, UnknownAddress
from .address import ScriptOutput as ScriptOutputBase
from .transaction import BCDataStream, Transaction, get_address_from_output_script

# 'lns:' URI scheme. Not used yet. Used by Crescent Cash and Electron Cash and
# other wallets in the future.
URI_SCHEME = 'lns'

class ArgumentError(ValueError):
    '''Raised by various LNS functions if the supplied args are bad or
    out of spec.'''

#### Lookup & Verification

class Info(namedtuple("Info", "name, address, registrationDate, expiryDate")):
    @classmethod
    def from_dict(cls, dict):
        dict['address'] = Address.from_cashaddr_string(dict['address'])
        tup = Info(**dict)
        return tup

    def to_dict(self):
        d = self._asdict()
        d['address'] = self.address.to_cashaddr()
        return d

servers = [
    "https://graph.bch.domains/subgraphs/name/graphprotocol/ens",
]

debug = False  # network debug setting. Set to True when developing to see more verbose information about network operations.
timeout = 25.0  # default timeout used in various network functions, in seconds.

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
from web3 import Web3
w3 = Web3(Web3.HTTPProvider("https://smartbch.fountainhead.cash/mainnet"))
contract = w3.eth.contract(address="0x0efB8EE0F6d6ba04F26101683F062d7Ca6F58A40", abi=abi)

def validate(name):
    if not name or not len(name):
        raise ArgumentError("Please pass a non-empty 'name' to lookup")
    if isinstance(name, List):
        for n in name:
            strict = LNS.parse_string(n)[1]
            if not strict:
                raise ArgumentError("Strictly full names required (including .bch)")

def lookup(server, name: Union[str, List[str]], timeout=timeout, exc=[], debug=debug) -> List[Info]:
    ''' Synchronous lookup, returns a List[Info] or None on error.

    Optionally, pass a list as the `exc` parameter and the exception encountered
    will be returned to caller by appending to the list.

    Use `name` as search term to narrow the search, otherwise too many
    results (if any) are returned and execution might timeout.

    Use `name` as a list of strict LNS names to lookup these names

    Name matching is case-insensitive. Also, name can be a substring and not a
    complete LNS domain name.
    '''
    validate(name)

    url = f'{server}'
    now = int(time.time())
    batch = 425 # number which fits into gas limit
    skip = 0
    def get_json(skip):
        if isinstance(name, list) or isinstance(name, set):
            names = [str.split(n.strip(), '.bch')[0] for n in name]
            return {"query": f'{{registrations(first:{batch},skip:{skip},where:{{labelName_in:{json.dumps(names)},expiryDate_gt:"{now}"}}){{labelName,registrationDate,expiryDate}}}}'}
        else:
            lookupName = str.split(name.strip(), '.bch')[0]
            return {"query": f'{{registrations(first:{batch},skip:{skip},where:{{labelName_contains:"{lookupName}",expiryDate_gt:"{now}"}}){{labelName,registrationDate,expiryDate}}}}'}

    try:
        ret = []
        moreToLoad = True
        while moreToLoad:
            r = requests.post(url, json=get_json(skip), allow_redirects=True, timeout=timeout) # will raise requests.exceptions.Timeout on timeout
            r.raise_for_status()
            d = r.json()
            if not isinstance(d, dict) or not d.get('data'):
                raise RuntimeError('Unexpected response', r.text)
            res = d['data']
            registrations = res['registrations']
            if not isinstance(registrations, list):
                raise RuntimeError('Bad response')

            if (len(registrations)):
                names = [d['labelName'] + '.bch' for d in registrations]
                COIN_TYPE_BCH = 145
                addrs = contract.functions.getAddrs(names, COIN_TYPE_BCH).call()
                filtered = [dict(reg, addr=addr)  for (reg, addr) in zip(registrations,addrs) if addr != b'']

                for reg in filtered:
                    ret.append(
                        Info(
                            reg['labelName'] + '.bch',
                            # Address.from_cashaddr_string("qqevtgm50kulte70smem643qs07fjkj47y5jv2d2v7"),
                            get_address_from_output_script(reg['addr'])[1],
                            int(reg['registrationDate']),
                            int(reg['expiryDate'])
                        ))

            if (len(registrations) == batch):
                skip += batch
            else:
                moreToLoad = False

        return ret
    except Exception as e:
        if debug:
            util.print_error("lookup:", repr(e))
        if isinstance(exc, list):
            exc.append(e)

def lookup_asynch(server, success_cb, error_cb=None,
                  name=None, timeout=timeout, debug=debug):
    ''' Like lookup() above, but spawns a thread and does its lookup
    asynchronously.

    success_cb - will be called on successful completion with a single arg:
                 a List[Info].
    error_cb   - will be called on failure with a single arg: the exception
                 (guaranteed to be an Exception subclass).

    In either case one of the two callbacks will be called. It's ok for
    success_cb and error_cb to be the same function (in which case it should
    inspect the arg passed to it). Note that the callbacks are called in the
    context of the spawned thread, (So e.g. Qt GUI code using this function
    should not modify the GUI directly from the callbacks but instead should
    emit a Qt signal from within the callbacks to be delivered to the main
    thread as usual.) '''

    def thread_func():
        exc = []
        res = lookup(server=server, name=name, timeout=timeout, exc=exc, debug=debug)
        called = False
        if res is None:
            if callable(error_cb) and exc:
                error_cb(exc[-1])
                called = True
        else:
            success_cb(res)
            called = True
        if not called:
            # this should never happen
            util.print_error("WARNING: no callback called for ", threading.current_thread().name)
    t = threading.Thread(name=f"LNS lookup_asynch: {server} ({name},{timeout})",
                         target=thread_func, daemon=True)
    t.start()

def lookup_asynch_all(success_cb, error_cb=None, name=None,
                      timeout=timeout, debug=debug):
    ''' Like lookup_asynch above except it tries *all* the hard-coded servers
    from `servers` and if all fail, then calls the error_cb exactly once.
    If any succeed, calls success_cb exactly once.

    Note: in this function success_cb is called with TWO args:
      - first arg is the List[Item]
      - the second arg is the 'server' that was successful (server string)

    One of the two callbacks are guaranteed to be called in either case.

    Callbacks are called in another thread context so GUI-facing code should
    be aware of that fact (see nodes for lookup_asynch above).  '''
    assert servers, "No servers hard-coded in lns.py. FIXME!"
    my_servers = servers.copy()
    random.shuffle(my_servers)
    N = len(my_servers)
    q = queue.Queue()
    lock = threading.Lock()
    n_ok, n_err = 0, 0
    def on_succ(res, server):
        nonlocal n_ok
        q.put(None)
        with lock:
            if debug: util.print_error("success", n_ok+n_err, server)
            if n_ok:
                return
            n_ok += 1
        success_cb(res, server)
    def on_err(exc, server):
        nonlocal n_err
        q.put(None)
        with lock:
            if debug: util.print_error("error", n_ok+n_err, server, exc)
            if n_ok:
                return
            n_err += 1
            if n_err < N:
                return
        if error_cb:
            error_cb(exc)
    def do_lookup_all_staggered():
        ''' Send req. out to all servers, staggering the requests every 200ms,
        and stopping early after the first success.  The goal here is to
        maximize the chance of successful results returned, with tolerance for
        some servers being unavailable, while also conserving on bandwidth a
        little bit and not unconditionally going out to ALL servers.'''
        t0 = time.time()
        for i, server in enumerate(my_servers):
            if debug: util.print_error("server:", server, i)
            lookup_asynch(server,
                          success_cb = lambda res, _server=server: on_succ(res, _server),
                          error_cb = lambda exc, _server=server: on_err(exc, _server),
                          name = name, timeout = timeout,
                          debug = debug)
            try:
                q.get(timeout=0.200)
                while True:
                    # Drain queue in case previous iteration's servers also
                    # wrote to it while we were sleeping, so that next iteration
                    # the queue is hopefully empty, to increase the chances
                    # we get to sleep.
                    q.get_nowait()
            except queue.Empty:
                pass
            with lock:
                if n_ok:  # check for success
                    if debug:
                        util.print_error(f"do_lookup_all_staggered: returning "
                                         f"early on server {i} of {len(my_servers)} after {(time.time()-t0)*1e3} msec")
                    return
    t = threading.Thread(daemon=True, target=do_lookup_all_staggered)
    t.start()

class LNS(util.PrintError):
    ''' Class implementing LNS subsystem such as verification, etc. '''

    def __init__(self, wallet):
        assert wallet, "LNS cannot be instantiated without a wallet"
        self.wallet = wallet
        self.lock = threading.Lock()  # note, this lock is subordinate to wallet.lock and should always be taken AFTER wallet.lock and never before

        self._init_data()

        # below is used by method self.verify_name_asynch:
        self._names_in_flight = defaultdict(list)  # number (eg 100-based-modified height) -> List[tuple(success_cb, error_cb)]; guarded with lock

    def _init_data(self):
        self.v_by_addr = defaultdict(set) # dict of addr -> set of txid
        self.v_by_name = defaultdict(set) # dict of lowercased name -> set of txid

    def invalidate(self):
        try:
            # ten minutes
            QTimer.singleShot(10 * 60 * 1000, self.invalidate)
            with self.lock:
                self._init_data()
        except:
            pass

    def diagnostic_name(self):
        return f'{self.wallet.diagnostic_name()}.{__class__.__name__}'

    def start(self, network):
        # start invalidation sequence
        self.invalidate()

    def stop(self):
        pass

    def fmt_info(self, info : Info) -> str:
        ''' Given an Info object, returns a string of the form:
        satoshi.bch
        '''
        return info.name

    @classmethod
    def parse_string(cls, s : str) -> Tuple[str, bool]:
        ''' Returns a (name, bool) tuple on parse success
        Bool indicates strictly formatted LNS name ending on .bch
        Does not raise, merely returns None on all errors.'''

        return s.strip(), s.endswith('.bch')

    def resolve_verify(self, lns_string: str, timeout: float = timeout, exc: list = None) -> List[Info]:
        ''' Blocking resolver for LNS Names. Given a lns_string of the
        form: satoshi.bch, will verify the name existence, check that
        BCH address was set for this record and do other magic.
        It will return a list of tuple of (Info, minimal_chash).

        This goes out to the network each time, so use it in GUI code that
        really needs to know verified LNS Names (eg before sending funds),
        but not in advisory GUI code, since it can be slow (on the order of less
        than a second to several seconds depending on network speed).

        timeout is a timeout in seconds. If timer expires None is returned.

        It will return None on failure or nothing found.

        Optional arg `exc` is where to put the exception on network or other
        failure. '''

        validate(lns_string)
        done = threading.Event()
        pb = None
        def done_cb(thing):
            nonlocal pb
            if isinstance(thing, List):
                pb = thing
            elif isinstance(thing, Exception) and isinstance(exc, list):
                self.wallet.show_error(str(thing))
                exc.append(thing)
            done.set()
        self.verify_name_asynch(name=lns_string, success_cb=done_cb, error_cb=done_cb, timeout=timeout)
        if not done.wait(timeout=timeout) or not pb:
            return
        return pb;

    def get_lns_names(self, domain=None, inv=False) -> List[Info]:
        ''' Returns a list of Info objects for verified LNS Names in domain.
        Domain must be an iterable of addresses (either wallet or external).
        If domain is None, every verified cash account we know about is returned.

        If inv is True, then domain specifies addresses NOT to include
        in the results (i.e. eevery verified LNS Name we know about not in
        domain be returned). '''
        if domain is None:
            domain = self.v_by_addr if not inv else set()
        ret = []
        seen = set()
        with self.lock:
            if inv:
                domain = set(self.v_by_addr) - set(domain)
            for addr in domain:
                infos = self.v_by_addr.get(addr, set())
                for info in infos:
                    if info and info not in seen:
                        seen.add(info)
                        ret.append(info)

        return ret

    def get_wallet_lns_names(self) -> List[Info]:
        ''' Convenience method, returns all the verified cash accounts we
        know about for wallet addresses only. '''
        return self.get_lns_names(domain=self.wallet.get_addresses())

    def get_external_lns_names(self) -> List[Info]:
        ''' Convenience method, retruns all the verified cash accounts we
        know about that are not for wallet addresses. '''
        return self.get_lns_names(domain=self.wallet.get_addresses(), inv=True)

    def load(self):
        ''' Note: loading should happen before threads are started, so no lock
        is needed.'''
        self._init_data()

        # we do good just by verifying names in contact list upon launch
        # we do not to persist all names fetched, but I leave the code here for now

        # try:
        #     dd = self.wallet.storage.get('lns_data', {})

        #     for cashaddr, infos in dd.get('v_by_addr', {}).items():
        #         self.v_by_addr[Address.from_cashaddr_string(cashaddr)] = set([Info.from_dict(dict) for dict in infos])
        #     for name, infos in dd.get('v_by_name', {}).items():
        #         self.v_by_name[name] = set([Info.from_dict(dict) for dict in infos])
        # except:
        #     pass

    def save(self, write=False):
        '''
        FYI, current data model is:

        self.v_by_addr = defaultdict(set) # dict of addr -> set of txid
        self.v_by_name = defaultdict(set) # dict of lowercased name -> set of txid
        '''
        # ignore saving data for now
        return

        data =  {
                    'v_by_addr' : {},
                    'v_by_name' : {},
                }
        for idx, key in enumerate(self.v_by_addr):
            data['v_by_addr'][key.to_cashaddr()] = [x.to_dict() for x in list(self.v_by_addr[key])]
        for idx, key in enumerate(self.v_by_name):
            data['v_by_name'][key] = [x.to_dict() for x in list(self.v_by_name[key])]

        self.wallet.storage.put('lns_data', data)
        if write:
            self.wallet.storage.write()

    def get_verified(self, lns_name) -> Info:
        ''' Returns the Info object for lns_name of the form: satoshi.bch
        or None if not found in self.v_by_name '''
        tup = self.parse_string(lns_name)
        if tup:
            name, _strict = tup
            l = self.find_verified(name=name)
            if len(l):
                return l[0]

    def find_verified(self, name: str) -> List[Info]:
        ''' Returns a list of Info objects for verified LNS Names matching
        lowercased name.
        '''
        ret = []
        with self.lock:
            name = name.lower()
            s = self.v_by_name.get(name, set())
            for info in s:
                if info:
                    if info.name.lower() != name:
                        self.print_error(f"find: FIXME -- v_by_name has inconsistent data for name {name} != {info.name}")
                        continue
                    ret.append(info)

        return ret

    @staticmethod
    def _do_verify_name_argchecks(network, exc=[], server='https://unknown'):
        if not isinstance(server, str) or not server:
            raise ArgumentError('bad server arg')
        if not isinstance(exc, list):
            raise ArgumentError('bad exc arg')
        if not network:
            exc.append(RuntimeError('no network'))
            return False
        return True

    def verify_name_asynch(self, name=None, success_cb=None, error_cb=None, timeout=timeout, debug=debug):
        ''' Tries all servers. Calls success_cb with the verified List[Info]
        as the single argument on first successful retrieval of the block.
        Calls error_cb with the exc as the only argument on failure. Guaranteed
        to call 1 of the 2 callbacks in either case.  Callbacks are optional
        and won't be called if specified as None. '''
        exc = []
        # network = self.network # capture network object in case it goes away while we are running
        # if not self._do_verify_name_argchecks(network=network, exc=exc):
        #     if error_cb: error_cb((exc and exc[-1]) or RuntimeError('error'))
        #     return
        key = json.dumps(list(name))
        def on_error(exc):
            with self.lock:
                l = self._names_in_flight.pop(key, [])
            ct = 0
            for success_cb, error_cb in l:
                if error_cb:
                    error_cb(exc)
                    ct += 1
            if debug: self.print_error(f"verify_name_asynch: called {ct} error callbacks for #{key}")
        def on_success(res, server):
            pb = res;
            if isinstance(pb, List):
                with self.lock:
                    for item in pb:
                        self.v_by_name[item.name].add(item)
                        self.v_by_addr[item.address].add(item)
                    self.save(True)
                    l = self._names_in_flight.pop(key, [])
                ct = 0
                for success_cb, error_cb in l:
                    if success_cb:
                        success_cb(pb)
                        ct += 1
                if debug: self.print_error(f"verify_name_asynch: called {ct} success callbacks for #{key}")
            else:
                on_error(exc[-1])
        with self.lock:
            l = self._names_in_flight[key]
            l.append((success_cb, error_cb))
            if len(l) == 1:
                if debug: self.print_error(f"verify_name_asynch: initiating new lookup_asynch_all on #{key}")
                lookup_asynch_all(name=name, success_cb=on_success, error_cb=on_error, timeout=timeout, debug=debug)
            else:
                if debug: self.print_error(f"verify_name_asynch: #{key} already in-flight, will just enqueue callbacks")

    ############################
    # UI / Prefs / Convenience #
    ############################

    def get_address_default(self, infos : List[Info]) -> Info:
        ''' Returns the preferred Info object for a particular address from
        a given list. `infos' is a list of Info objects pertaining to a
        particular address (they should all pertain to said address, but this
        is not checked). '''
        if infos:
            last = infos[-1]
            d = self.wallet.storage.get('lns_address_defaults')
            if isinstance(d, dict) and isinstance(last.address, Address):  # sanity check, .address may not always be Address but may be UnknownAddress
                tup = d.get(last.address.to_storage_string())
                if isinstance(tup, (tuple, list)) and len(tup) == 3:
                    name, number, chash = tup
                    if isinstance(name, str) and isinstance(number, (int, float)) and isinstance(chash, str):
                        # find the matching one in the list
                        for info in infos:
                            if (name.lower(), number, chash) == (info.name.lower(), info.number, info.collision_hash):
                                return info
            # just return the latest one if no default specified
            return last

    def set_address_default(self, info : Info):
        ''' Set the default LNS Name for a particular address. Pass the Info
        object pertaining to the LNS Name / Address in question. '''
        if not isinstance(info.address, Address):
            self.print_error("Warning: Info object does not have an Address", info)
            return
        d = self.wallet.storage.get('lns_address_defaults', {})
        addr_str = info.address.to_storage_string()
        new_value = [info.name, info.number, info.collision_hash]
        d[addr_str] = new_value
        self.wallet.storage.put('lns_address_defaults', d)
