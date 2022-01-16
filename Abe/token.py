#!/usr/bin/env python
# Copyright(C) 2022 pacprotocol

from BCDataStream import *
from enumeration import Enumeration
from base58 import public_key_to_bc_address, hash_160_to_bc_address
import logging
import socket
import time
import binascii
from util import short_hex, long_hex
import struct

def decode_token(bytes):

  stack_data = ''
  for byte in bytes:
    stack_data += short_hex(byte)

  print ('original: ' + stack_data)

  # start with testing for OP_TOKEN
  stack_byte = stack_data[:2]
  stack_data = stack_data[2:]
  if 'b3' not in stack_byte:
     return 'INVALID'

  # check type of operation
  stack_byte = stack_data[:2]
  stack_data = stack_data[2:]

  # checksum data
  if '00' in stack_byte:                            # OP_0
     stack_byte = stack_data[:2]
     stack_data = stack_data[2:]
     if '75' in stack_byte:                         # OP_DROP
        stack_byte = stack_data[:2]
        stack_data = stack_data[2:]
        if '76' in stack_byte:                      # OP_DUP
            stack_byte = stack_data[:2]
            stack_data = stack_data[2:]
            if 'a9' in stack_byte:                  # OP_HASH160
                stack_byte = stack_data[:40]
                stack_data = stack_data[40:]
                return stack_byte                   # 20byte checksum

  # token version
  stack_byte = stack_data[:2]
  stack_data = stack_data[2:]
  token_version = int(stack_byte, 16) - 80
  if token_version not in range(1,16):
      return None

  # token type
  stack_byte = stack_data[:2]
  stack_data = stack_data[2:]
  token_type = int(stack_byte, 16)
  if token_type not in range(1,2):
      return None

  # token id
  stack_byte = stack_data[:2]
  stack_data = stack_data[2:]
  token_id = int(stack_byte, 16)

  # namelen
  stack_byte = stack_data[:2]
  stack_data = stack_data[2:]
  name_len = int(stack_byte, 16)

  # name
  name = ''
  stack_byte = stack_data[:name_len*2]
  stack_data = stack_data[name_len*2:]
  while name_len > 0:
     current_byte = stack_byte[:2]
     current_int = int(current_byte, 16)
     name += chr(current_int)
     stack_byte = stack_byte[2:]
     name_len -= 1

  # address
  stack_data = stack_data[8:].replace('76a914','').replace('88ac','')
  bytes = binascii.unhexlify(stack_data)
  address = hash_160_to_bc_address(bytes, version='\x37')

  # construct token event
  tokenout = 'token (' + name + ') to address ' + address

  return tokenout
