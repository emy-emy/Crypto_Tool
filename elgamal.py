import random
import math
import sys

class PrivateKey(object):
	def __init__(self, p=None, g=None, x=None, iNumBits=0):
		self.p = p    # Nombre premier pour les calculs  modulo
		self.g = g    # Générateur (racine primitive modulo p)
		self.x = x       # Clé privée 
		self.iNumBits = iNumBits  # Taille en bits de la clé

class PublicKey(object):
	def __init__(self, p=None, g=None, h=None, iNumBits=0):
		self.p = p   # Même nombre premier que dans la clé privée
		self.g = g   # Même générateur
		self.h = h     # Calculé comme h = g^x mod p, donc dépend de la clé privée
		self.iNumBits = iNumBits

def gcd( a, b ):
		while b != 0:
			c = a % b
			a = b
			b = c
		return a

def modexp( base, exp, modulus ):
		return pow(base, exp, modulus)

def SS( num, iConfidence ):
		for i in range(iConfidence):
				a = random.randint( 1, num-1 )

				if gcd( a, num ) > 1:
						return False

				if not jacobi( a, num ) % num == modexp ( a, (num-1)//2, num ):
						return False

		return True

def jacobi( a, n ):
		if a == 0:
				if n == 1:
						return 1
				else:
						return 0
		elif a == -1:
				if n % 2 == 0:
						return 1
				else:
						return -1
		elif a == 1:
				return 1
		elif a == 2:
				if n % 8 == 1 or n % 8 == 7:
						return 1
				elif n % 8 == 3 or n % 8 == 5:
						return -1
		elif a >= n:
				return jacobi( a%n, n)
		elif a%2 == 0:
				return jacobi(2, n)*jacobi(a//2, n)
		
		else:
				if a % 4 == 3 and n%4 == 3:
						return -1 * jacobi( n, a)
				else:
						return jacobi(n, a )



def find_primitive_root( p ):
		if p == 2:
				return 1
		
		p1 = 2
		p2 = (p-1) // p1

		while( 1 ):
				g = random.randint( 2, p-1 )
				
				if not (modexp( g, (p-1)//p1, p ) == 1):
						if not modexp( g, (p-1)//p2, p ) == 1:
								return g

def find_prime(iNumBits, iConfidence):
		while(1):
				p = random.randint( 2**(iNumBits-2), 2**(iNumBits-1) )
				while( p % 2 == 0 ):
						p = random.randint(2**(iNumBits-2),2**(iNumBits-1))

				while( not SS(p, iConfidence) ):
						p = random.randint( 2**(iNumBits-2), 2**(iNumBits-1) )
						while( p % 2 == 0 ):
								p = random.randint(2**(iNumBits-2), 2**(iNumBits-1))

				
				p = p * 2 + 1
				if SS(p, iConfidence):
						return p

def encode(sPlaintext, iNumBits):
		byte_array = bytearray(sPlaintext, 'utf-16')

		z = []

		
		k = iNumBits//8

		j = -1 * k
		num = 0
		for i in range( len(byte_array) ):
				if i % k == 0:
						j += k
						num = 0
						z.append(0)
				z[j//k] += byte_array[i]*(2**(8*(i%k)))

	

		return z

def decode(aiPlaintext, iNumBits):
		bytes_array = []

		
		k = iNumBits//8

		for num in aiPlaintext:
				for i in range(k):
						temp = num
						for j in range(i+1, k):
								temp = temp % (2**(8*j))
						letter = temp // (2**(8*i))
						bytes_array.append(letter)
						
						num = num - (letter*(2**(8*i)))

		

		decodedText = bytearray(b for b in bytes_array).decode('utf-16')

		return decodedText

def generate_keys(iNumBits=256, iConfidence=32):
		
		p = find_prime(iNumBits, iConfidence)
		g = find_primitive_root(p)
		g = modexp( g, 2, p )
		x = random.randint( 1, (p - 1) // 2 )
		h = modexp( g, x, p )

		publicKey = PublicKey(p, g, h, iNumBits)
		privateKey = PrivateKey(p, g, x, iNumBits)

		return {'privateKey': privateKey, 'publicKey': publicKey}


def encrypt(key, sPlaintext):
		z = encode(sPlaintext, key.iNumBits)

		cipher_pairs = []
		for i in z:
				y = random.randint( 0, key.p )
				c = modexp( key.g, y, key.p )
				d = (i*modexp( key.h, y, key.p)) % key.p
				cipher_pairs.append( [c, d] )

		encryptedStr = ""
		for pair in cipher_pairs:
				encryptedStr += str(pair[0]) + ' ' + str(pair[1]) + ' '
	
		return encryptedStr


def decrypt(key, cipher):
		plaintext = []

		cipherArray = cipher.split()
		if (not len(cipherArray) % 2 == 0):
				return "Malformed Cipher Text"
		for i in range(0, len(cipherArray), 2):
				c = int(cipherArray[i])
				d = int(cipherArray[i+1])

				
				s = modexp( c, key.x, key.p )
				plain = (d*modexp( s, key.p-2, key.p)) % key.p
				plaintext.append( plain )

		decryptedText = decode(plaintext, key.iNumBits)

		decryptedText = "".join([ch for ch in decryptedText if ch != '\x00'])

		return decryptedText


