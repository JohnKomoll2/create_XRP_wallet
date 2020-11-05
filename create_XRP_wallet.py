# Turn family seed into an XRPL keypair and corresponding public address
#
# derivation scheme:   https://xrpl.org/cryptographic-keys.html
#                      https://xrpl.org/accounts.html
#
# adapted from Ripple source:
#                      https://github.com/ripple/xrpl-dev-portal/blob/master/content/_code-samples/key-derivation/key_derivation.py
#                      
# Author: John Komoll
#

# import modules
import argparse
import hashlib
from hashlib import sha512, sha256
from secrets import randbits
from secp256k1prp import PrivateKey
import ed25519
import base58
from Crypto.Util import RFC1751   # if there is an error here, try "from crypto.Util"

# give prefixes
XRPL_SEED_PREFIX = b'\x21'                 # integer   33
XRPL_ACCT_PUBKEY_PREFIX = b'\x23'          # integer   35
XRPL_VALIDATOR_PUBKEY_PREFIX = b'\x1c'     # integer   28
XRPL_ADDRESS_PREFIX = b'\x00'              # integer    0
ED_PREFIX = b'\xed'                        # integer  237

# define secp256k1 Q param
SECP256K1_Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# define function to turn seed buffer into seed bytes
def buf_to_seed(seed_buf):
    """
    turn base58, RFC-1751, hexadecimal, or XUMM secret number seed buffer into seed bytes
    seed_buf --> base58, rippled RFC-1751, hexadecimal, or XUMM secret number seed buffers
    """
    # first try base58
    try:
        seedtry = base58.b58decode_check(seed_buf, alphabet=base58.RIPPLE_ALPHABET)
        if seedtry[:1] == XRPL_SEED_PREFIX and len(seedtry) == 17:
            seed_bytes = seedtry[1:]
            return seed_bytes
        else:
            raise ValueError
    except:
        pass

    # next try RFC-1751 (rippled format)
    try:
        seedtry = RFC1751.english_to_key(seed_buf)
        if len(seedtry) == 16:
            _RFC1751_format = input('rippled API format? type True or False:  ').lower()
            if _RFC1751_format == "true" or _RFC1751_format == "t":
                seed_bytes = int.from_bytes(seedtry, byteorder='little').to_bytes(16, byteorder='big')
            else:
                seed_bytes = seedtry
            return seed_bytes
        else:
            raise ValueError
    except:
        pass

    # next try hexadecimal
    try:
        bytetry = bytes.fromhex(seed_buf)
        if len(bytetry) == 16:
            seed_bytes = bytetry
            return seed_bytes
        else:
            raise ValueError
    except:
        pass

    # next try XUMM secret number
    try:
        if len(seed_buf) == 48:
            seed_bytes = b''
            for row in range(8):
                seed_bytes = seed_bytes + int(seed_buf[row*6:row*6+5]).to_bytes(2, byteorder='big')
                if int(seed_buf[row*6:row*6+5]) * (row * 2 + 1) % 9 != int(seed_buf[row*6+5]):
                    raise ValueError
            return seed_bytes
        else:
            raise ValueError
    except:
        pass

    # if none of the above, raise error
    raise Exception('input seed is not base58, RFC-1751, hexadecimal, or secret number')

# define secp256k1 function to turn seed buffer into seed bytes
def secp256k1_hash_seed(seed):
    """
    Calculate a valid secp256k1 secret key by hashing a seed
    if invalid secp256k1 key is found, augment seed by 1 byte and 
    try again
    seed --> seed bytes to hash
    """
    root_seq = 0  # counter augmented when invalid key is found

    # loop thru seed, adding 1 byte, until valid secp256k1 key is found
    while True:
        buf = seed + root_seq.to_bytes(4, byteorder="big", signed=False)
        # get first 32 bytes and integer of SHA-512 hash of seed + root_seq
        sha512half = sha512(buf).digest()[:32]
        sha512half_int = int.from_bytes(sha512half, byteorder="big", signed=False)
        if sha512half_int < SECP256K1_Q and sha512half_int != 0:
            return sha512half_int
        # else, not a valid secp256k1 key, augment root_seq and try again
        root_seq += 1

# define the wallet class
class Wallet:
    """
    An XRP wallet with valid private and public keys for use 
    on the XRP ledger. 
    """
    
    def __init__(self, seed_buf=None, input_passphrase=None):
        """
        seed_buf --> base58, RFC-1751, or hexadecimal seed buffers
        passphrase --> string of text to hash into a seed
        """
        # Initialize public-private keypair variables
        self._secret_key_secp256k1 = None
        self._public_key_secp256k1 = None
        self._root_secret_key_secp256k1 = None
        self._root_public_key_secp256k1 = None
        self._account_ID_secp256k1 = None
        self._public_address_secp256k1 = None
        self._secret_key_Ed25519 = None
        self._public_key_Ed25519 = None
        self._account_ID_Ed25519 = None
        self._public_address_Ed25519 = None
        self._bytes = None

        # get seed from Wallet inputs
        if input_passphrase is not None:
            # send error if both seed and passphrase are given
            if seed_buf is not None:
                raise Exception('Cannot give seed AND passphrase')
            # turn passphrase into seed
            else:
                passphrase_utf8 = input_passphrase.encode("UTF-8")
                self._bytes = sha512(passphrase_utf8).digest()[:16]
        else:
            # generate random seed if no buffer given
            if seed_buf is None:
                self._bytes = randbits(16*8).to_bytes(16, byteorder="big")
            # convert seed buffer to seed
            else:
                self._bytes = buf_to_seed(seed_buf)
        return
    
    # define seed property of Wallet
    @property
    def seed(self):
        """
        16-byte seed (bytes)
        """
        return self._bytes
    
    # define hexadecimal seed property from seed bytes
    @property
    def seed_hexadecimal(self):
        """
        Wallet seed in hexadecimal buffer representation
        """
        return self._bytes.hex().upper()

    # define base58 seed property from seed bytes
    @property
    def seed_base58(self):
        """
        Wallet seed in XRPL base58 representation
        """
        return base58.b58encode_check(XRPL_SEED_PREFIX + self._bytes, alphabet=base58.RIPPLE_ALPHABET).decode()

    # define RFC-1751 seed property from seed bytes
    @property
    def seed_RFC1751(self):
        """
        Wallet seed in RFC-1751 mnemonic representation
        """
        return RFC1751.key_to_english(int.from_bytes(self._bytes, byteorder='big').to_bytes(16, byteorder='little'))

    # define XUMM secret number property for seed
    @property
    def seed_secret_num(self):
        """
        Wallet seed in secret number format (dictionary, 8 rows of 6 digits)
        """
        # initialize dictionary to hold 8 rows of secret nums, using keys 1-8
        _dict = {}

        # loop thru each 2 bytes to generate each row of secret numbers
        for _bytepair in range(int(len(self._bytes)/2)):
            _int = int.from_bytes(self._bytes[_bytepair*2:_bytepair*2+2], byteorder='big')
            _checksum = _int * (_bytepair * 2 + 1) % 9
            _dict[str(_bytepair+1)] = str(_int).rjust(5, '0') + str(_checksum)
        
        return _dict
    
    # define root_secret_key property of Wallet
    @property
    def root_secret_key_secp256k1(self):
        """
        32-byte secp256k1 root secret key (bytes), used for validators
        """
        if self._root_secret_key_secp256k1 is None:
            self.generate_secp256k1_keypair()
        return self._root_secret_key_secp256k1
    
    # define root_public_key property of Wallet
    @property
    def root_public_key_secp256k1(self):
        """
        33-byte secp256k1 root public key (bytes)
        """
        if self._root_public_key_secp256k1 is None:
            self.generate_secp256k1_keypair()
        return self._root_public_key_secp256k1
    
    # define base58_validator property of Wallet
    @property
    def base58_validator_secp256k1(self):
        """
        secp256k1 root public key validator (base58)
        """
        if self._root_public_key_secp256k1 is None:
            self.generate_secp256k1_keypair()
        return base58.b58encode_check(XRPL_VALIDATOR_PUBKEY_PREFIX + self._root_public_key_secp256k1, alphabet=base58.RIPPLE_ALPHABET).decode()
    
    # define public_key property of Wallet
    @property
    def public_key_secp256k1(self):
        """
        33-byte secp256k1 public key (bytes)
        """
        if self._public_key_secp256k1 is None:
            self.generate_secp256k1_keypair()
        return self._public_key_secp256k1
    
    # define hexadecimal public_key property of Wallet
    @property
    def public_key_secp256k1_hex(self):
        """
        33-byte secp256k1 public key (hexadecimal)
        """
        if self._public_key_secp256k1 is None:
            self.generate_secp256k1_keypair()
        return self._public_key_secp256k1.hex().upper()
    
    # define base58 public_key property of Wallet
    @property
    def public_key_secp256k1_base58(self):
        """
        secp256k1 public key (base58)
        """
        if self._public_key_secp256k1 is None:
            self.generate_secp256k1_keypair()
        return base58.b58encode_check(XRPL_ACCT_PUBKEY_PREFIX + self._public_key_secp256k1, alphabet=base58.RIPPLE_ALPHABET).decode()
    
    # define secret_key property of Wallet
    @property
    def secret_key_secp256k1(self):
        """
        32-byte secp256k1 secret key (bytes)
        """
        if self._secret_key_secp256k1 is None:
            self.generate_secp256k1_keypair()
        return self._secret_key_secp256k1
    
    # define hexadecimal secret_key property of Wallet
    @property
    def secret_key_secp256k1_hex(self):
        """
        32-byte secp256k1 secret key (hexadecimal)
        """
        if self._secret_key_secp256k1 is None:
            self.generate_secp256k1_keypair()
        return self._secret_key_secp256k1.hex().upper()

    # define account ID property
    @property
    def account_ID_secp256k1(self):
        """
        20-byte Account ID (bytes)
        """
        if self._account_ID_secp256k1 is None:
            _sha256_hash = sha256(self.public_key_secp256k1).digest()
            _RIPEMD160_hasher = hashlib.new('ripemd160')
            _RIPEMD160_hasher.update(_sha256_hash)
            self._account_ID_secp256k1 = _RIPEMD160_hasher.digest()
        return self._account_ID_secp256k1

    # define public address
    @property
    def public_address_secp256k1(self):
        """
        25-byte public address, including prefix 0x00 and 4-byte checksum (XRPL base58)
        """
        if self._public_address_secp256k1 is None:
            _sha256_hash1 = sha256(XRPL_ADDRESS_PREFIX + self.account_ID_secp256k1).digest()
            _sha256_hash2 = sha256(_sha256_hash1).digest()
            self._public_address_secp256k1 = base58.b58encode(XRPL_ADDRESS_PREFIX + self.account_ID_secp256k1 + _sha256_hash2[0:4], alphabet=base58.RIPPLE_ALPHABET)
        return self._public_address_secp256k1
    
    # define Ed25519 secret key property
    @property
    def secret_key_Ed25519(self):
        """
        32-byte Ed25519 secret key (bytes)
        """
        if self._secret_key_Ed25519 is None:
            self.generate_Ed25519_keypair()
        return self._secret_key_Ed25519
    
    # define Ed25519 secret key property in hex
    @property
    def secret_key_Ed25519_hex(self):
        """
        32-byte Ed25519 secret key (hex)
        """
        if self._secret_key_Ed25519 is None:
            self.generate_Ed25519_keypair()
        return self._secret_key_Ed25519.hex().upper()

    # define Ed25519 public key property
    @property
    def public_key_Ed25519(self):
        """
        33-byte Ed25519 public key (bytes)
        """
        if self._public_key_Ed25519 is None:
            self.generate_Ed25519_keypair()
        return self._public_key_Ed25519

    # define Ed25519 public key property in hex
    @property
    def public_key_Ed25519_hex(self):
        """
        33-byte Ed25519 public key (hex)
        """
        if self._public_key_Ed25519 is None:
            self.generate_Ed25519_keypair()
        return self._public_key_Ed25519.hex().upper()
    
    # define Ed25519 account ID property
    @property
    def account_ID_Ed25519(self):
        """
        20-byte Ed25519 Account ID (bytes)
        """
        if self._account_ID_Ed25519 is None:
            _sha256_hash = sha256(self.public_key_Ed25519).digest()
            _RIPEMD160_hasher = hashlib.new('ripemd160')
            _RIPEMD160_hasher.update(_sha256_hash)
            self._account_ID_Ed25519 = _RIPEMD160_hasher.digest()
        return self._account_ID_Ed25519

    # define Ed25519 public address
    @property
    def public_address_Ed25519(self):
        """
        25-byte public address, including prefix 0x00 and 4-byte checksum (XRPL base58)
        """
        if self._public_address_Ed25519 is None:
            _sha256_hash1 = sha256(XRPL_ADDRESS_PREFIX + self.account_ID_Ed25519).digest()
            _sha256_hash2 = sha256(_sha256_hash1).digest()
            self._public_address_Ed25519 = base58.b58encode(XRPL_ADDRESS_PREFIX + self.account_ID_Ed25519 + _sha256_hash2[0:4], alphabet=base58.RIPPLE_ALPHABET)
        return self._public_address_Ed25519
    
    # define method to generate secp256k1 XRP keypair from a seed
    def generate_secp256k1_keypair(self):
        """
        Return _root_public_key, _public_key, and _secret_key from Wallet seed
        """
        # derive a valid secp256k1 root secret key integer from seed
        root_secret_key_int = secp256k1_hash_seed(self._bytes)
        root_secret_key_b = root_secret_key_int.to_bytes(32, byteorder='big', signed=False)
        # derive public key point
        root_PrivateKey = PrivateKey(root_secret_key_b)
        root_PublicKey = root_PrivateKey.pubkey
        # store 33-byte compressed key and uncompressed key
        root_public_key_b = root_PublicKey.serialize()

        # derive a valid intermediate secp256k1 secret key from compressed root public key
        interm_secret_key_int = secp256k1_hash_seed(b''.join([root_public_key_b, bytes(4)]))
        # derive intermediate secp256k1 public key point
        interm_PrivateKey = PrivateKey(interm_secret_key_int.to_bytes(32, byteorder="big", signed=False))

        # calculate master secret key from root, intermediate integers
        master_secret_key_int = (root_secret_key_int + interm_secret_key_int) % SECP256K1_Q
        master_secret_key_b = master_secret_key_int.to_bytes(32, byteorder='big')
        master_PrivateKey = PrivateKey(master_secret_key_b)
        # calculate master public key from master private key
        master_PublicKey = master_PrivateKey.pubkey

        # set Wallet instance variables
        self._secret_key_secp256k1 = master_secret_key_b
        self._public_key_secp256k1 = master_PublicKey.serialize()
        self._root_secret_key_secp256k1 = root_secret_key_b
        self._root_public_key_secp256k1 = root_public_key_b
    
    # define method to generate Ed25519 XRP keypair from a seed
    def generate_Ed25519_keypair(self):
        """
        Return _root_public_key, _public_key, and _secret_key from Wallet seed
        """
        # take SHA-512 half hash of seed for private key and create Ed25519 SigningKey instance
        self._secret_key_Ed25519 = sha512(self._bytes).digest()[:32]
        Ed25519_SigningKey = ed25519.SigningKey(self._secret_key_Ed25519)

        # derive public key from Ed25519 private key
        self._public_key_Ed25519 = ED_PREFIX + Ed25519_SigningKey.get_verifying_key().to_bytes()
        
# setup modular functionality, parsing inputs
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("-seed", default=None)
    p.add_argument("-password", default=None)
    args = p.parse_args()

    wallet = Wallet(args.seed, args.password)
    wallet.generate_secp256k1_keypair()

    print("""
    Seed (base58): {base58}
    Seed (hex): {hex}
    Seed (RFC-1751, rippled API format): {rfc1751}
    Seed (XUMM secret numbers): {sec_row1} {sec_row2} {sec_row3} {sec_row4} {sec_row5} {sec_row6} {sec_row7} {sec_row8}

    secp256k1 Secret Key (hex): {secp256k1_secret}
    secp256k1 Public Key (hex): {secp256k1_public}
    secp256k1 Public Key (base58 - Account): {secp256k1_pub_base58}
    secp256k1 Public Key (base58 - Validator): {secp256k1_pub_base58_val}
    secp256k1 Account ID: {secp256k1_account_ID}
    secp256k1 Public Address: {secp256k1_public_address}

    Ed25519 Secret Key (hex): {Ed25519_secret}
    Ed25519 Public Key (hex): {Ed25519_public}
    Ed25519 Account ID: {Ed25519_account_ID}
    Ed25519 Public Address: {Ed25519_public_address}
    """.format(base58 = wallet.seed_base58,
            hex = wallet.seed_hexadecimal,
            rfc1751 = wallet.seed_RFC1751,
            sec_row1 = wallet.seed_secret_num['1'],
            sec_row2 = wallet.seed_secret_num['2'],
            sec_row3 = wallet.seed_secret_num['3'],
            sec_row4 = wallet.seed_secret_num['4'],
            sec_row5 = wallet.seed_secret_num['5'],
            sec_row6 = wallet.seed_secret_num['6'],
            sec_row7 = wallet.seed_secret_num['7'],
            sec_row8 = wallet.seed_secret_num['8'],
            secp256k1_secret = wallet.secret_key_secp256k1_hex,
            secp256k1_public = wallet.public_key_secp256k1_hex,
            secp256k1_pub_base58 = wallet.public_key_secp256k1_base58,
            secp256k1_pub_base58_val = wallet.base58_validator_secp256k1,
            secp256k1_account_ID = wallet.account_ID_secp256k1,
            secp256k1_public_address = wallet.public_address_secp256k1,
            Ed25519_secret = wallet.secret_key_Ed25519_hex,
            Ed25519_public = wallet.public_key_Ed25519_hex,
            Ed25519_account_ID = wallet.account_ID_Ed25519,
            Ed25519_public_address = wallet.public_address_Ed25519))