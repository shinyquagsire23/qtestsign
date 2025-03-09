# SPDX-License-Identifier: GPL-2.0-only AND BSD-3-Clause
# Copyright (C) 2021-2023 Stephan Gerhold (GPL-2.0-only)
# MBN header format adapted from:
#   - signlk: https://git.linaro.org/landing-teams/working/qualcomm/signlk.git
#   - coreboot (util/qualcomm/mbn_tools.py)
# Copyright (c) 2016, 2018, The Linux Foundation. All rights reserved. (BSD-3-Clause)
# See also:
#   - https://www.qualcomm.com/media/documents/files/secure-boot-and-image-authentication-technical-overview-v1-0.pdf
#   - https://www.qualcomm.com/media/documents/files/secure-boot-and-image-authentication-technical-overview-v2-0.pdf
from __future__ import annotations

import dataclasses
import hashlib
from dataclasses import dataclass
from io import BytesIO
from struct import Struct
import struct

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature, Prehashed

from pyasn1.codec.der.decoder import decode
from pyasn1.type.univ import Sequence, Integer

from . import cert
from . import elf

# A typical Qualcomm firmware might have the following program headers:
#     LOAD off    0x00000800 vaddr 0x86400000 paddr 0x86400000 align 2**11
#          filesz 0x00001000 memsz 0x00001000 flags rwx
#
# The signed version will then look like:
#     NULL off    0x00000000 vaddr 0x00000000 paddr 0x00000000 align 2**0
#          filesz 0x000000e8 memsz 0x00000000 flags --- 7000000
#     NULL off    0x00001000 vaddr 0x86401000 paddr 0x86401000 align 2**12
#          filesz 0x00000988 memsz 0x00001000 flags --- 2200000
#     LOAD off    0x00002000 vaddr 0x86400000 paddr 0x86400000 align 2**11
#          filesz 0x00001000 memsz 0x00001000 flags rwx
#
# The second NULL program header with off 0x1000 and filesz 0x988 is the actual
# "hash table segment" or shortly "hash segment" (see Figure 2 on page 6 in the PDF).
# It contains the MBN header specified below, then a couple of hashes (e.g. SHA256):
#   1. Hash of ELF header and program headers
#   2. Empty hash for hash segment
#   3. Hashes for data of each memory segment (described by program header)
# Finally, it contains an RSA signature and the concatenated certificate chain.
#
# The first NULL program header is never loaded anywhere, because
# vaddr = paddr = memsz = 0. However, the "off" and "filesz" cover exactly
# the ELF header (including all program headers). It is a placeholder so that
# each hash covers the data of exactly one program header.

PHDR_FLAGS_HDR_PLACEHOLDER = 0x70  # placeholder for hash over ELF header
PHDR_FLAGS_HASH_SEGMENT    = 0x22  # hash table segment
PHDR_FLAGS_HASH_SEGMENT_V7 = 0x20  # hash table segment (V7 onwards)

EXTRA_PHDRS = 2  # header placeholder + hash segment

# Note: None of the alignments seem to be truly required,
# this could probably be reduced to get smaller file sizes.
HASH_SEG_ALIGN = 0x1000
CERT_CHAIN_ALIGN = 16

# According to the v2.0 PDF the metadata is 128 bytes long, but this does not
# seem to work. All official firmware seems to use 120 bytes instead.
METADATA_SIZE_V6 = 120

# V7 is different from V6
COMMON_METADATA_SIZE_V7 = 0x18
QTI_OEM_METADATA_SIZE_V7 = 0xE0
CERT_CHAIN_SIZE_V7 = 0xD20
SIGNATURE_SIZE_SECP384R1 = 0x68

def hex_string(b):
	p = ""
	b = bytes(b)
	for i in range(0, len(b)):
		p += ("%02x" % b[i])
	return p

def hex_dump(b, prefix=""):
	p = prefix
	b = bytes(b)
	for i in range(0, len(b)):
		if i != 0 and i % 16 == 0:
			print (p)
			p = prefix
		p += ("%02x " % b[i])
	print (p)

def _align(i: int, alignment: int) -> int:
	mask = max(alignment - 1, 0)
	return (i + mask) & ~mask

def split_der_cert_chain(der_data: bytes):
	"""
	Splits a concatenated DER-encoded certificate chain into individual certificates.
	
	:param der_data: A byte string containing multiple DER-encoded certificates.
	:return: A list of individual DER-encoded certificate byte strings.
	"""
	certs = []
	i = 0
	while i < len(der_data):
		if der_data[i] != 0x30:  # ASN.1 SEQUENCE tag (X.509 starts with 0x30)
			raise ValueError(f"Unexpected tag at index {i}: {hex(der_data[i])}")
		
		# Read the length (ASN.1 DER uses definite length encoding)
		length = der_data[i + 1]
		if length & 0x80:  # Long form length
			num_bytes = length & 0x7F  # Number of bytes used for length
			length = int.from_bytes(der_data[i + 2 : i + 2 + num_bytes], byteorder="big")
			header_length = 2 + num_bytes  # SEQUENCE tag + length bytes
		else:  # Short form length
			header_length = 2  # SEQUENCE tag + 1 length byte

		cert_length = header_length + length
		certs.append(der_data[i : i + cert_length])  # Extract the certificate
		i += cert_length  # Move to the next certificate

	return certs

def load_certificates(cert_chain_der: bytes):
	certs = []
	for cert_der in cert_chain_der:
		certs.append(x509.load_der_x509_certificate(bytes(cert_der)))
	return certs

def load_ecdsa_signature(der_bytes: bytes):
	signature_seq, _ = decode(der_bytes, asn1Spec=Sequence())
	r = int(signature_seq[0])  # First INTEGER (r)
	s = int(signature_seq[1])  # Second INTEGER (s)
	return encode_dss_signature(r, s)

def extract_raw_hash(signature: bytes, pub_key: rsa.RSAPublicKey, hashfn):
	hash_size = hashfn().digest_size
	
	try:
		decrypted = pub_key.recover_data_from_signature(
			signature,
			padding.PKCS1v15(),
			None
		)
	except:
		# Probably RSA-PSS
		return None
	
	if len(decrypted) != hash_size:
		print("Weird RSA data?")
		hex_dump(decrypted)
		return None
	
	return decrypted

def mbn_hmac(hashed_data: bytes, sw_id: int, hw_id: int, hashfn):
	i_pad = 0x3636363636363636
	o_pad = 0x5c5c5c5c5c5c5c5c

	h0 = hashfn(hashed_data).digest()
	h1 = hashfn(struct.pack(">Q", sw_id ^ i_pad) + h0).digest()
	return hashfn(struct.pack(">Q", hw_id ^ o_pad) + h1).digest()

@dataclass
class _HashSegment:
	image_id: int = 0  # Type of image (unused?)
	version: int = 0  # Header version number

	hash_size = 0
	signature_size_oem = 0
	cert_chain_size_oem = 0
	total_size = 0

	hashes = []
	signature_oem = b''
	cert_chain_oem = b''

	FORMAT = Struct('<10L')
	Hash = hashlib.sha256

	@property
	def size_with_header(self):
		return self.FORMAT.size + self.total_size

	def update(self, dest_addr: int):
		self.hash_size = len(self.hashes) * self.Hash().digest_size
		self.signature_size_oem = len(self.signature_oem)
		self.cert_chain_size_oem = len(self.cert_chain_oem)
		self.total_size = self.hash_size + self.signature_size_oem + self.cert_chain_size_oem

	def check(self):
		assert len(self.hashes) * self.Hash().digest_size == self.hash_size
		assert len(self.signature_oem) == self.signature_size_oem
		assert len(self.cert_chain_oem) == self.cert_chain_size_oem

	def pack_header(self):
		self.check()
		return self.FORMAT.pack(*dataclasses.astuple(self))

	def pack(self):
		return self.pack_header() \
			+ b''.join(self.hashes) \
			+ self.signature_oem + self.cert_chain_oem

	def pack_sigchecked(self):
		return self.pack_header() \
			+ b''.join(self.hashes)

	def pack_sigchecked_qti(self):
		return self.pack_sigchecked()

	def pack_sigchecked_oem(self):
		return self.pack_sigchecked()

	@classmethod
	def unpack(cls, data: bytes):
		offs = 0
		self = cls(*cls.FORMAT.unpack(data[:cls.FORMAT.size]))
		offs += self.FORMAT.size
		print(cls)
		
		self.hashes = []
		for i in range(0, self.hash_size, self.Hash().digest_size):
			self.hashes += [data[offs:offs+self.Hash().digest_size]]
			offs += self.Hash().digest_size

		self.signature_oem = data[offs:offs+self.signature_size_oem]
		offs += self.signature_size_oem
		self.cert_chain_oem = data[offs:offs+self.cert_chain_size_oem]
		self.check()
		return self


@dataclass
class HashSegmentV3(_HashSegment):
	version: int = 3  # Header version number

	flash_addr: int = 0  # Location of image in flash (historical)
	dest_addr: int = 0  # Physical address of loaded hash segment data
	total_size: int = 0  # = hash_size + signature_size_oem + cert_chain_size_oem
	hash_size: int = 0  # Size of hashes for all program segments
	signature_addr_oem: int = 0  # Physical address of loaded attestation signature
	signature_size_oem: int = 0  # Size of attestation signature
	cert_chain_addr_oem: int = 0  # Physical address of loaded certificate chain
	cert_chain_size_oem: int = 0  # Size of certificate chain

	def update(self, dest_addr: int):
		super().update(dest_addr)
		self.dest_addr = dest_addr + self.FORMAT.size
		self.signature_addr_oem = self.dest_addr + self.hash_size
		self.cert_chain_addr_oem = self.signature_addr_oem + self.signature_size_oem


@dataclass
class HashSegmentV5(_HashSegment):
	version: int = 5  # Header version number

	signature_size_qti: int = 0  # Size of signature from Qualcomm
	cert_chain_size_qti: int = 0  # Size of certificate chain from Qualcomm
	total_size: int = 0  # = hash_size + signature_size_oem + cert_chain_size_oem
	hash_size: int = 0  # Size of hashes for all program segments
	signature_addr_oem: int = 0xffffffff  # unused?
	signature_size_oem: int = 0  # Size of attestation signature
	cert_chain_addr_oem: int = 0xffffffff  # unused?
	cert_chain_size_oem: int = 0  # Size of certificate chain

	signature_qti = b''
	cert_chain_qti = b''

	def update(self, dest_addr: int):
		super().update(dest_addr)
		self.signature_size_qti = len(self.signature_qti)
		self.cert_chain_size_qti = len(self.cert_chain_qti)
		self.total_size += self.signature_size_qti + self.cert_chain_size_qti

	def check(self):
		super().check()
		assert len(self.signature_qti) == self.signature_size_qti
		assert len(self.cert_chain_qti) == self.cert_chain_size_qti

	def pack(self):
		return self.pack_header() \
			+ b''.join(self.hashes) \
			+ self.signature_qti + self.cert_chain_qti \
			+ self.signature_oem + self.cert_chain_oem

	def pack_sigchecked_qti(self):
		tmp1 = self.signature_size_oem
		tmp2 = self.cert_chain_size_oem
		self.signature_size_oem = 0
		self.cert_chain_size_oem = 0
		ret = self.FORMAT.pack(*dataclasses.astuple(self)) \
			+ b''.join(self.hashes)
		self.signature_size_oem = tmp1
		self.cert_chain_size_oem = tmp2
		return ret

	def pack_sigchecked_oem(self):
		tmp1 = self.signature_size_qti
		tmp2 = self.cert_chain_size_qti
		self.signature_size_qti = 0
		self.cert_chain_size_qti = 0
		ret = self.FORMAT.pack(*dataclasses.astuple(self)) \
			+ b''.join(self.hashes)
		self.signature_size_qti = tmp1
		self.cert_chain_size_qti = tmp2
		return ret

	@classmethod
	def unpack(cls, data: bytes):
		offs = 0
		self = cls(*cls.FORMAT.unpack(data[:cls.FORMAT.size]))
		offs += self.FORMAT.size
		
		self.hashes = []
		for i in range(0, self.hash_size, self.Hash().digest_size):
			self.hashes += [data[offs:offs+self.Hash().digest_size]]
			offs += self.Hash().digest_size

		self.signature_qti = data[offs:offs+self.signature_size_qti]
		offs += self.signature_size_qti
		self.cert_chain_qti = data[offs:offs+self.cert_chain_size_qti]
		offs += self.cert_chain_size_qti
		self.signature_oem = data[offs:offs+self.signature_size_oem]
		offs += self.signature_size_oem
		self.cert_chain_oem = data[offs:offs+self.cert_chain_size_oem]
		self.check()
		return self


@dataclass
class HashSegmentV6(HashSegmentV5):
	version: int = 6  # Header version number

	# TODO: Compare against V7 and verify the order of these
	metadata_size_qti: int = 0  # Size of metadata from Qualcomm
	metadata_size_oem: int = 0  # Size of metadata

	metadata_qti = b''
	metadata_oem = b''

	FORMAT = Struct('<12L')
	Hash = hashlib.sha384

	def update(self, dest_addr: int):
		super().update(dest_addr)
		self.metadata_size_qti = len(self.metadata_qti)
		self.metadata_size_oem = len(self.metadata_oem)
		self.total_size += self.metadata_size_qti + self.metadata_size_oem

	def check(self):
		super().check()
		assert len(self.metadata_qti) == self.metadata_size_qti
		assert len(self.metadata_oem) == self.metadata_size_oem

	def pack(self):
		return self.pack_header() \
			+ self.metadata_qti + self.metadata_oem \
			+ b''.join(self.hashes) \
			+ self.signature_qti + self.cert_chain_qti \
			+ self.signature_oem + self.cert_chain_oem

	def pack_sigchecked(self):
		return self.pack_header() \
			+ bytes(self.metadata_qti) + bytes(self.metadata_oem) \
			+ b''.join(self.hashes)

	def pack_sigchecked_qti(self):
		tmp1 = self.signature_size_oem
		tmp2 = self.cert_chain_size_oem
		self.signature_size_oem = 0
		self.cert_chain_size_oem = 0
		ret = self.FORMAT.pack(*dataclasses.astuple(self)) \
			+ bytes(self.metadata_qti) + len(self.metadata_oem)*b'\x00' \
			+ b''.join(self.hashes)
		self.signature_size_oem = tmp1
		self.cert_chain_size_oem = tmp2
		return ret

	def pack_sigchecked_oem(self):
		tmp1 = self.signature_size_qti
		tmp2 = self.cert_chain_size_qti
		self.signature_size_qti = 0
		self.cert_chain_size_qti = 0
		ret = self.FORMAT.pack(*dataclasses.astuple(self)) \
			+ len(self.metadata_qti)*b'\x00'+ bytes(self.metadata_oem) \
			+ b''.join(self.hashes)
		self.signature_size_qti = tmp1
		self.cert_chain_size_qti = tmp2
		return ret

	@classmethod
	def unpack(cls, data: bytes):
		offs = 0
		self = cls(*cls.FORMAT.unpack(data[:cls.FORMAT.size]))
		offs += self.FORMAT.size
		self.metadata_qti = data[offs:offs+self.metadata_size_qti]
		offs += self.metadata_size_qti
		self.metadata_oem = data[offs:offs+self.metadata_size_oem]
		offs += self.metadata_size_oem
		
		self.hashes = []
		for i in range(0, self.hash_size, self.Hash().digest_size):
			self.hashes += [data[offs:offs+self.Hash().digest_size]]
			offs += self.Hash().digest_size

		self.signature_qti = data[offs:offs+self.signature_size_qti]
		offs += self.signature_size_qti
		self.cert_chain_qti = data[offs:offs+self.cert_chain_size_qti]
		offs += self.cert_chain_size_qti
		self.signature_oem = data[offs:offs+self.signature_size_oem]
		offs += self.signature_size_oem
		self.cert_chain_oem = data[offs:offs+self.cert_chain_size_oem]
		self.check()
		return self

# V7 breaks from the prior versions and only keeps the image_id and version fields
@dataclass
class HashSegmentV7():
	image_id: int = 0  # Type of image (unused?)
	version: int = 7  # Header version number

	# See also: https://www.qualcomm.com/content/dam/qcomm-martech/dm-assets/documents/secure-boot-and-image-authentication.pdf
	# (Figure 5)
	metadata_size_common: int = 0
	metadata_size_qti: int = 0
	metadata_size_oem: int = 0
	hash_size: int = 0
	signature_size_qti: int = 0
	cert_chain_size_qti: int = 0
	signature_size_oem: int = 0
	cert_chain_size_oem: int = 0

	metadata_common = b''
	metadata_qti = b''
	metadata_oem = b''
	hashes = b''
	signature_qti = b''
	cert_chain_qti = b''
	signature_oem = b''
	cert_chain_oem = b''

	FORMAT = Struct('<10L')
	Hash = hashlib.sha384

	@property
	def size_with_header(self):
		return self.FORMAT.size + sum(dataclasses.astuple(self)[2:]) + CERT_CHAIN_SIZE_V7 # why?

	def update(self, dest_addr: int):
		self.metadata_size_common = len(self.metadata_common)
		self.metadata_size_qti = len(self.metadata_qti)
		self.metadata_size_oem = len(self.metadata_oem)
		self.hash_size = len(self.hashes) * self.Hash().digest_size
		self.signature_size_qti = len(self.signature_qti)
		self.cert_chain_size_qti = len(self.cert_chain_qti)
		self.signature_size_oem = len(self.signature_oem)
		self.cert_chain_size_oem = len(self.cert_chain_oem)

	def check(self):
		assert len(self.metadata_common) == self.metadata_size_common
		assert len(self.metadata_qti) == self.metadata_size_qti
		assert len(self.metadata_oem) == self.metadata_size_oem
		assert len(self.hashes) * self.Hash().digest_size == self.hash_size
		assert len(self.signature_qti) == self.signature_size_qti
		assert len(self.cert_chain_qti) == self.cert_chain_size_qti
		assert len(self.signature_oem) == self.signature_size_oem
		assert len(self.cert_chain_oem) == self.cert_chain_size_oem

	def pack_header(self):
		self.check()
		return self.FORMAT.pack(*dataclasses.astuple(self))

	def pack_sigchecked(self):
		return self.pack_header() \
			+ bytes(self.metadata_common) + bytes(self.metadata_qti) + bytes(self.metadata_oem) \
			+ b''.join(self.hashes)

	def pack_sigchecked_qti(self):
		tmp1 = self.signature_size_oem
		tmp2 = self.cert_chain_size_oem
		self.signature_size_oem = 0
		self.cert_chain_size_oem = 0
		ret = self.FORMAT.pack(*dataclasses.astuple(self)) \
			+ bytes(self.metadata_common) + bytes(self.metadata_qti) + len(self.metadata_oem)*b'\x00' \
			+ b''.join(self.hashes)
		self.signature_size_oem = tmp1
		self.cert_chain_size_oem = tmp2
		return ret

	def pack_sigchecked_oem(self):
		tmp1 = self.signature_size_qti
		tmp2 = self.cert_chain_size_qti
		self.signature_size_qti = 0
		self.cert_chain_size_qti = 0
		ret = self.FORMAT.pack(*dataclasses.astuple(self)) \
			+ bytes(self.metadata_common)  + len(self.metadata_qti)*b'\x00'+ bytes(self.metadata_oem) \
			+ b''.join(self.hashes)
		self.signature_size_qti = tmp1
		self.cert_chain_size_qti = tmp2
		return ret

	def pack(self):
		return self.pack_sigchecked() \
			+ self.signature_qti + self.cert_chain_qti \
			+ self.signature_oem + self.cert_chain_oem + (b'\xFF'*CERT_CHAIN_SIZE_V7) # why?

	@classmethod
	def unpack(cls, data: bytes):
		offs = 0

		data = bytes(data)

		self = cls(*cls.FORMAT.unpack(data[:cls.FORMAT.size]))
		offs += self.FORMAT.size

		self.metadata_common = data[offs:offs+self.metadata_size_common]
		offs += self.metadata_size_common
		self.metadata_qti = data[offs:offs+self.metadata_size_qti]
		offs += self.metadata_size_qti
		self.metadata_oem = data[offs:offs+self.metadata_size_oem]
		offs += self.metadata_size_oem

		self.hashes = []
		for i in range(0, self.hash_size, self.Hash().digest_size):
			self.hashes += [data[offs:offs+self.Hash().digest_size]]
			offs += self.Hash().digest_size

		self.signature_qti = data[offs:offs+self.signature_size_qti]
		offs += self.signature_size_qti
		self.cert_chain_qti = data[offs:offs+self.cert_chain_size_qti]
		offs += self.cert_chain_size_qti
		self.signature_oem = data[offs:offs+self.signature_size_oem]
		offs += self.signature_size_oem
		self.cert_chain_oem = data[offs:offs+self.cert_chain_size_oem]

		if len(self.cert_chain_qti) < self.cert_chain_size_qti:
			self.cert_chain_qti += b'\xFF' * (self.cert_chain_size_qti - len(self.cert_chain_qti))

		if len(self.signature_oem) < self.signature_size_oem:
			self.signature_oem += b'\xFF' * (self.signature_size_oem - len(self.signature_oem))

		if len(self.cert_chain_oem) < self.cert_chain_size_oem:
			self.cert_chain_oem += b'\xFF' * (self.cert_chain_size_oem - len(self.cert_chain_oem))
		
		self.check()
		return self


HashSegment = {
	3: HashSegmentV3,
	5: HashSegmentV5,
	6: HashSegmentV6,
	7: HashSegmentV7,
}


def drop(elff: elf.Elf):
	# Drop existing hash segments
	elff.phdrs = [phdr for phdr in elff.phdrs if phdr.p_type != 0 or (phdr.p_flags >> 20) not in
				  [PHDR_FLAGS_HASH_SEGMENT, PHDR_FLAGS_HASH_SEGMENT_V7, PHDR_FLAGS_HDR_PLACEHOLDER]]


def generate(elff: elf.Elf, version: int, sw_id: int):
	drop(elff)
	assert elff.phdrs, "Need at least one program header"

	hash_seg = HashSegment[version]()

	# TODO: Figure out metadata format and fill this with useful data
	if version == 6:
		hash_seg.metadata_common = b'\0' * METADATA_SIZE_V6
	elif version == 7:
		hash_seg.metadata_common = b'\0' * COMMON_METADATA_SIZE_V7

	# Generate hash for all existing segments with data
	digest_size = hash_seg.Hash().digest_size
	hash_seg.hashes = [b'\0' * digest_size] * (len(elff.phdrs) + EXTRA_PHDRS)
	start_idx = EXTRA_PHDRS if version < 7 else 0
	for i, phdr in enumerate(elff.phdrs, start=start_idx):
		idx = i if version < 7 else i+1
		if phdr.data:
			hash_seg.hashes[idx] = hash_seg.Hash(phdr.data).digest()
	total_hashes_size = len(hash_seg.hashes) * digest_size

	# Generate certificate chain with specified OU fields (for < v6)
	# on >= v6 this is part of the metadata instead
	ou_fields = []
	if version < 6:
		ou_fields = [
			# Note: The SW_ID is checked by the firmware on some platforms (even if secure boot
			# is disabled), so it must match the firmware type being signed. Everything else seems
			# to be mostly ignored when secure boot is off and is just added here to match the
			# documentation and better mimic the official firmware.
			"01 %016X SW_ID" % sw_id,
			"02 %016X HW_ID" % 0,
			"03 %016X DEBUG" % 2,  # DISABLED
			"04 %04X OEM_ID" % 0,
			"05 %08X SW_SIZE" % (hash_seg.FORMAT.size + total_hashes_size),
			"06 %04X MODEL_ID" % 0,
			"07 %04X SHA256" % 1,
		]
	hash_seg.cert_chain = cert.generate_chain(ou_fields)
	hash_seg.cert_chain = hash_seg.cert_chain.ljust(_align(len(hash_seg.cert_chain), CERT_CHAIN_ALIGN), b'\xff')
	# hash_seg.cert_chain = b''  # uncomment this to omit the certificate chain in the signed image

	# TODO: Generate actual signature with our generated attestation certificate!
	# There are different signature schemes that could be implemented (RSASSA-PKCS#1 v1.5
	# RSASSA-PSS, ECDSA over P-384) but it's not entirely clear yet which chipsets supports/
	# uses which. The signature does not seem to be checked on devices without secure boot,
	# so just use a dummy value for now.
	hash_seg.signature_oem = b'\xff' * (cert.ATT_KEY.key_size // 8)
	# hash_seg.signature_oem = b''  # uncomment this to omit the signature in the signed image
	
	# TODO real fake signing
	'''
	from cryptography.hazmat.primitives.asymmetric import utils
	from cryptography.hazmat.primitives import hashes
	from cryptography.hazmat.primitives.asymmetric import ec
	from cryptography.hazmat.backends import default_backend

	# Generate a private key for secp384r1
	private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

	# Get the public key from the private key
	public_key = private_key.public_key()

	# Sign a message
	signature = private_key.sign(hash_seg.pack_sigchecked(), ec.ECDSA(hashes.SHA384()))

	# Verify the signature
	try:
		public_key.verify(signature, hash_seg.pack_sigchecked(), ec.ECDSA(hashes.SHA384()))
		print("Signature verification successful!")
	except Exception as e:
		print("Signature verification failed:", e)
	'''

	if version >= 7:
		hash_seg.metadata_common = struct.pack("<LLLLLL", 0, 0, sw_id, 0, 3, 0)

		# In version 7, the signature and cert have to be valid ASN.1
		hash_seg.metadata_oem = struct.pack("<LL", 2, 0) + (QTI_OEM_METADATA_SIZE_V7-8) * b"\x00"
		hash_seg.signature_oem = SIGNATURE_SIZE_SECP384R1 * b'\x00'
		hash_seg.cert_chain_oem = CERT_CHAIN_SIZE_V7 * b'\x00'

		# In version 7, the signature and cert have to be valid ASN.1
		hash_seg.metadata_qti = struct.pack("<LL", 2, 0) + (QTI_OEM_METADATA_SIZE_V7-8) * b"\x00"
		hash_seg.signature_qti = SIGNATURE_SIZE_SECP384R1 * b'\x00'
		hash_seg.cert_chain_qti = CERT_CHAIN_SIZE_V7 * b'\x00'

	# Align maximum end address to get address for hash table header, then update header
	hash_offs = HASH_SEG_ALIGN
	hash_addr = _align(max(phdr.p_paddr + phdr.p_memsz for phdr in elff.phdrs), HASH_SEG_ALIGN)
	hash_seg.update(hash_addr)
	hash_memsz = _align(hash_seg.size_with_header, HASH_SEG_ALIGN) # Note: 0x6000 maximum
	if version >= 7:
		hash_offs = _align(max(phdr.p_offset for phdr in elff.phdrs), HASH_SEG_ALIGN)
		hash_addr = 0
		hash_memsz = hash_seg.size_with_header
	print(hash_seg)

	# Insert new hash NULL segment
	hash_phdr = elf.Phdr(0, hash_offs, hash_addr, hash_addr, hash_seg.size_with_header,
						 hash_memsz,
						 (PHDR_FLAGS_HASH_SEGMENT_V7 if version >= 7 else PHDR_FLAGS_HASH_SEGMENT) << 20, 
						 HASH_SEG_ALIGN)
	if version < 7:
		elff.phdrs.insert(0, hash_phdr)
	else:
		#hash_phdr.p_filesz = 0x00002cd0
		hash_phdr.p_memsz = hash_phdr.p_filesz
		elff.phdrs.append(hash_phdr)

	# Insert new ELF header placeholder program header
	hdr_hash_phdr = elf.Phdr(0, 0, 0, 0, 0, 0, PHDR_FLAGS_HDR_PLACEHOLDER << 20, 0)
	elff.phdrs.insert(0, hdr_hash_phdr)

	# Now determine size of ELF header (including program headers)
	hdr_hash_phdr.p_filesz = elff.total_header_size()

	# Recompute attributes to match final output (e.g. adjust e_phnum)
	elff.update(keep_load_segment_offsets=(version>=7))

	# Compute the hash for the ELF header
	with BytesIO() as hdr_io:
		elff.save_header(hdr_io)
		hash_seg.hashes[0] = hash_seg.Hash(hdr_io.getbuffer()).digest()

	# Hash segment has no hash
	if version >= 7:
		hash_seg.hashes[-1] = b'\x00'*digest_size

	# And finally, assemble the hash segment
	hash_phdr.data = hash_seg.pack()

def dump(elff: elf.Elf, sect: elf.Phdr):
	if sect.data is None:
		return

	VERSION_CHECK = Struct('<LL')
	_, version = VERSION_CHECK.unpack(sect.data[:VERSION_CHECK.size])
	print(f"Hash Segment v{version}:")

	hash_seg = HashSegment[version].unpack(sect.data)

	empty_hash = b'\x00'*hash_seg.Hash().digest_size
	any_fails = False
	print("Index  Stored              Calculated")
	for i in range(0, len(elff.phdrs)):
		h = hash_seg.hashes[i]
		phdr = elff.phdrs[i]
		b = phdr.data
		
		str_stored = hex_string(h)
		str_check = hex_string(hash_seg.Hash(b).digest() if b is not None and (phdr.p_flags >> 20) not in [PHDR_FLAGS_HASH_SEGMENT, PHDR_FLAGS_HASH_SEGMENT_V7] else empty_hash)
		str_res = "OK" if str_stored == str_check else "FAIL"

		if str_stored != str_check:
			any_fails = True
		print(f"{i:02x}     {str_stored[:16]}... {str_check[:16]}...  {str_res}")

	if any_fails:
		print("FINAL...........................................FAIL!")
	else:
		print("FINAL...........................................OK!")

	print("")

	software_id = 0
	hardware_id = 0
	hashfn_idx = 2
	hashfn = hashlib.sha256
	hashfn_idx_to_fn = {
		2: hashlib.sha256,
		3: hashlib.sha384,
		5: hashlib.sha512
	}

	if hasattr(hash_seg, "metadata_common"):
		m = hash_seg.metadata_common
		print(f"Common Metadata: (0x{len(m):x} bytes)")

		# This seems to be a trend they're sticking with, major/minor u32s
		if version >= 6 and len(m) >= 8:
			major_version, minor_version = struct.unpack("<LL", m[:8])
			print(f"version = {major_version}.{minor_version}")
		
		if version >= 7:
			software_id, hardware_id_maybe, hashfn_idx, unk_14  = struct.unpack("<LLLL", hash_seg.metadata_common[8:])
			print(f"software_id  = 0x{software_id:x}")
			print(f"hardware_id_maybe = 0x{hardware_id_maybe:x}")
			print(f"hash_table_algorithm = 0x{hashfn_idx:x}") # 0=none 1=? 2=sha256 3=sha384 4=sha512
			print(f"unk_14 = 0x{unk_14:x}")
		else:
			hex_dump(hash_seg.metadata_common)

		print("")

	# TODO: Double check if this applies to the signature as well?
	hashfn = hashfn_idx_to_fn.get(hashfn_idx, None)
	hash_seg.Hash = hashfn

	if hasattr(hash_seg, "metadata_qti"):
		m = hash_seg.metadata_qti
		print(f"QTI Metadata: (0x{len(m):x} bytes)")
		
		# This seems to be a trend they're sticking with, major/minor u32s
		if version >= 6 and len(m) >= 8:
			major_version, minor_version = struct.unpack("<LL", m[:8])
			print(f"version = {major_version}.{minor_version}")

		hex_dump(hash_seg.metadata_qti)
		print("")
	
	if hasattr(hash_seg, "metadata_oem"):
		m = hash_seg.metadata_oem
		print(f"OEM Metadata: (0x{len(m):x} bytes)")

		# This seems to be a trend they're sticking with, major/minor u32s
		if version >= 6 and len(m) >= 8:
			major_version, minor_version = struct.unpack("<LL", m[:8])
			print(f"version = {major_version}.{minor_version}")

		hex_dump(hash_seg.metadata_oem)
		print("")

	# TODO print the ASN.1?
	if hasattr(hash_seg, "cert_chain_qti"):
		print(f"QTI cert chain: (0x{len(hash_seg.cert_chain_qti):x} bytes)")
		#hex_dump(hash_seg.cert_chain_qti)
		print("...")
		print("")

	if hasattr(hash_seg, "cert_chain_oem"):
		print(f"OEM cert chain: (0x{len(hash_seg.cert_chain_oem):x} bytes)")
		print("...")
		#hex_dump(hash_seg.cert_chain_oem)
		print("")

	def try_sig_chain_pair_rsa(sig_der: bytes, cert_chain_der: bytes, which_sig: str, authority: str):
		# TODO use cert.signature_hash_algorithm
		sig_der = bytes(sig_der)
		try:
			cert_chain_der_split = split_der_cert_chain(bytes(cert_chain_der).strip(b'\xFF'))
			cert_chain = load_certificates(cert_chain_der_split)
		except:
			print("Cert chain failed to load, image is probably corrupt or fakesigned.")
			return

		hash_fn = hash_seg.Hash
		hash_alg = cert_chain[0].signature_hash_algorithm

		sw_id = -1
		hw_id = -1
		for attr in cert_chain[0].subject:
			v = attr.value
			if "SW_ID" in v:
				sw_id = int(v.split(" ")[1], 16)
			elif "HW_ID" in v:
				hw_id = int(v.split(" ")[1], 16)

		# If we are able to, print out the signature digest
		rsa_hash = extract_raw_hash(sig_der, cert_chain[0].public_key(), hash_seg.Hash)
		sig_ok = True
		if rsa_hash:
			print("RSA digest stored      Calculated")
			
			calc_hash = mbn_hmac(hash_seg.pack_sigchecked(), sw_id, hw_id, hash_fn)
			print(hex_string(rsa_hash)[:16] + "...    " + hex_string(calc_hash)[:16])
			
			if rsa_hash == calc_hash:
				print("Hash OK!")
			else:
				print("Hash FAIL!")
				sig_ok = False
		else:
			print("RSA-PSS digest:")
			# TODO: The HMAC thing might have changed for v5/v6
			data = hash_seg.pack_sigchecked_qti() if which_sig == "OEM" else hash_seg.pack_sigchecked_qti()
			data = mbn_hmac(data, sw_id, hw_id, hash_fn)
			try:
				cert_chain[0].public_key().verify(sig_der, data, cert_chain[0].signature_algorithm_parameters, Prehashed(hash_alg))
				print("Hash OK!")
			except:
				print("Hash FAIL!")
				sig_ok = False

		if version > 3 and version < 7:
			print(f"TODO: Sigchecks for version {version}")
		elif not sig_ok:
			any_fails = True

	def try_sig_chain_pair(sig_der: bytes, cert_chain_der: bytes, which_sig: str, authority: str):
		# TODO use cert.signature_hash_algorithm
		try:
			cert_chain_der_split = split_der_cert_chain(bytes(cert_chain_der).strip(b'\xFF'))
			cert_chain = load_certificates(cert_chain_der_split)
			sig = load_ecdsa_signature(bytes(sig_der).strip(b'\xFF'))
		except:
			print("Failed to load cert chain or signature, probably RSA...?")
			#rsakey = RSA.importKey(cert_chain_der_split[0])
			return try_sig_chain_pair_rsa(sig_der, cert_chain_der, which_sig, authority)

		if len(cert_chain) < 1:
			return

		# TODO: determine the algo from the cert chain?
		any_successes = False
		working_type = "None"
		# Kinda overkill, but sometimes things get signed wrong and it might be neat to check.
		try:
			cert_chain[0].public_key().verify(sig, hash_seg.pack_sigchecked(), ec.ECDSA(hashes.SHA384()))
			if which_sig != authority:
				print(f"{which_sig} signature with {authority} certs successfully verified with data: QTI+OEM (??)")
			else:
				print(f"{which_sig} signature successfully verified with digest: QTI+OEM")
			any_successes = True
		except:
			pass
		try:
			cert_chain[0].public_key().verify(sig, hash_seg.pack_sigchecked_qti(), ec.ECDSA(hashes.SHA384()))
			if which_sig != authority:
				print(f"{which_sig} signature with {authority} certs successfully verified with data: QTI (??)")
			else:
				print(f"{which_sig} signature successfully verified with digest: QTI")
			any_successes = True
		except:
			pass
		try:
			cert_chain[0].public_key().verify(sig, hash_seg.pack_sigchecked_oem(), ec.ECDSA(hashes.SHA384()))
			if which_sig != authority:
				print(f"{which_sig} signature with {authority} certs successfully verified with data: OEM (??)")
			else:
				print(f"{which_sig} signature successfully verified with digest: OEM")
			any_successes = True
		except:
			pass
		
		if not any_successes and version >= 7:
			any_fails = True
		elif version > 3 and version < 7:
			print(f"TODO: Sigchecks for version {version}")


	# TODO: This is bare-minimum signature verification
	# (no cert chain checking)
	if hasattr(hash_seg, "signature_qti"):
		print(f"QTI signature: (0x{len(hash_seg.signature_qti):x} bytes)")
		hex_dump(hash_seg.signature_qti)
		print("")

		if len(hash_seg.signature_qti) > 0:
			if hasattr(hash_seg, "cert_chain_qti") and len(hash_seg.cert_chain_qti) > 0:
				try_sig_chain_pair(hash_seg.signature_qti, hash_seg.cert_chain_qti, "QTI", "QTI")
			if hasattr(hash_seg, "cert_chain_oem") and len(hash_seg.cert_chain_oem) > 0:
				try_sig_chain_pair(hash_seg.signature_qti, hash_seg.cert_chain_oem, "QTI", "OEM")
			print("")


	if hasattr(hash_seg, "signature_oem"):
		print(f"OEM signature: (0x{len(hash_seg.signature_oem):x} bytes)")
		hex_dump(hash_seg.signature_oem)
		print("")

		if len(hash_seg.signature_oem) > 0:
			if hasattr(hash_seg, "cert_chain_qti") and len(hash_seg.cert_chain_qti) > 0:
				try_sig_chain_pair(hash_seg.signature_oem, hash_seg.cert_chain_qti, "OEM", "QTI")
			if hasattr(hash_seg, "cert_chain_oem") and len(hash_seg.cert_chain_oem) > 0:
				try_sig_chain_pair(hash_seg.signature_oem, hash_seg.cert_chain_oem, "OEM", "OEM")
			print("")

	if any_fails:
		print("MBN did not verify.")
	else:
		print("MBN verified successfully.")


	