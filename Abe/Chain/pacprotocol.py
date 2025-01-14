# Copyright(C) 2014 by Abe developers.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/agpl.html>.

import x11_hash
from . import BaseChain
from .. import deserialize

class pacprotocol(BaseChain):
    """
    A blockchain with proof-of-stake as in Peercoin.
    """

    def block_header_hash(chain, header):
        return x11_hash.getPoWHash(header)

    def has_feature(chain, feature):
        return feature == 'nvc_proof_of_stake'
