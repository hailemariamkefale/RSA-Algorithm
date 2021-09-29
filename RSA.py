'''
             Group Members
      Name                       ID
1. Gizaw Agodo               UGR/8917/12
2. Adisu Motora              UGR/4230/12
3. Haile Dereje              UGR/2190/12
4. Hailemariam Kefale        UGR/0652/12
5. Muluken Hakim             UGR/1110/12
6. Metsnanat Asfaw           UGR/7631/12
7. Selamawit Siferh          UGR/1822/12
8. Yeabsira Driba            UGR/4951/12
'''

import random
from math import sqrt

def gcd(a, b):
    ''' Euclid's algorithm for determining the greatest common divisor '''
    while b != 0:
        a, b = b, a % b
    return a

def eea(a, b):
    ''' Extended Euclidean Algorithm '''
    if(a%b == 0):
        return(b,0,1)
    else:
        gcd,s,t = eea(b,a%b)
        s = s-((a//b) * t)
        return(gcd, t, s)

def multiplicative_inverse(e, tuotient):
    ''' Multiplicative inverse of e mod tuotient '''
    gcd, s, _ = eea(e, tuotient)
    if(gcd != 1):
        return None
    else:
        return s%tuotient

def is_prime(num):
    ''' Tests to see if a number is prime '''
    if num < 2: return False
    for i in range(2, int(sqrt(num))+1):
        if num % i == 0:
            return False
    return True

def generate_prime():

    ''' Generates a random prime with 512 bits by default '''

    first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                     31, 37, 41, 43, 47, 53, 59, 61, 67,
                     71, 73, 79, 83, 89, 97, 101, 103,
                     107, 109, 113, 127, 131, 137, 139,
                     149, 151, 157, 163, 167, 173, 179,
                     181, 191, 193, 197, 199, 211, 223,
                     227, 229, 233, 239, 241, 251, 257,
                     263, 269, 271, 277, 281, 283, 293,
                     307, 311, 313, 317, 331, 337, 347, 349]

    def getLowLevelPrime(n):
        '''Generate a prime candidate not divisible by first primes'''

        while True:
            prime_candidate = random.randrange(2**(n-1)+1, 2**n-1)

            for divisor in first_primes_list:
                if prime_candidate % divisor == 0 and divisor**2 <= prime_candidate:
                    break
                else:
                    return prime_candidate

    def isMillerRabinPassed(miller_rabin_candidate):
        '''Run 20 iterations of Rabin Miller Primality test'''

        maxDivisionsByTwo = 0
        evenComponent = miller_rabin_candidate-1

        while evenComponent % 2 == 0:
            evenComponent >>= 1
            maxDivisionsByTwo += 1
        assert(2**maxDivisionsByTwo * evenComponent == miller_rabin_candidate-1)

        def trialComposite(round_tester):
            if pow(round_tester, evenComponent,
                miller_rabin_candidate) == 1:
                return False
            for i in range(maxDivisionsByTwo):
                if pow(round_tester, 2**i * evenComponent, miller_rabin_candidate) == miller_rabin_candidate-1:
                    return False
            return True

        # Set number of trials here
        numberOfRabinTrials = 20
        for i in range(numberOfRabinTrials):
            round_tester = random.randrange(2,
                        miller_rabin_candidate)
            if trialComposite(round_tester):
                return False
        return True

    while True:
        n = 512 # we can change n to larger or smaller values
        prime_candidate = getLowLevelPrime(n)
        if not isMillerRabinPassed(prime_candidate):
            continue
        else:
            return prime_candidate

def generate_keypair():
    
    p = generate_prime()
    q = generate_prime()

    n = p * q

    tuotient = (p-1) * (q-1)

    # e - a coprime integer with tuotient
    e = random.randrange(1, tuotient)
    
    g = gcd(e, tuotient)
    while g != 1:
        e = random.randrange(1, tuotient)
        g = gcd(e, tuotient)

    d = multiplicative_inverse(e, tuotient)
    
    print("\nPublic key: \n-------------------\n", e, "|", n)
    print("\nPrivate key: \n------------------\n", d, "|", n)

    #Public key: (e, n) --- private key: (d, n)
    return ((e, n), (d, n))

def mod_exp(b, e, m):
    '''
    b - base, e - exponenet, m - mod
    '''
    # Modular Exponentiation
    x = 1
    power = b % m
    binary = bin(e) # return binary representation of e
    for i in binary[:1:-1]:
        if int(i) == 1:
            x = (x * power) % m
        power = (power * power) % m
    return x

def msgToNumber(msg):

    # alpha_num - is a collection of characters the algorithm works
    # the algorithm doesn't work if the message contains a character which is not in aloha_num
    alpha_num = '^^^^^^^^^^ 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$()*+,-./:;<=>?'

    x = ''
    for i in msg:
        x += str(alpha_num.index(i))
    
    return int(x)

def numberToMsg(num):
    alpha_num = '^^^^^^^^^^ 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$()*+,-./:;<=>?'
    num = str(num)
    msg = ''
    for i in range(0, len(num), 2):
        msg += alpha_num[int(num[i:i+2])]
    
    return msg

# ============================================= #
if __name__ == '__main__':

    print("\nRSA Encryption Algorithm :")
    print("\nGenerating public and private keys ...")
    public, private = generate_keypair()

    e, n = public # unboxing the tuple public
    d, n = private # unboxing the tuple private

    msg = input("\nEnter the message: ")
    msg_to_num = msgToNumber(msg) # changes the message to decimal representaion

    enc_msg = mod_exp(msg_to_num, e, n) # encrypted message using public key (e, n)
    print("\nEncrypted message:", enc_msg)

    dec_msg = mod_exp(enc_msg, d, n) # decrypted message using private key (d, n)
    print("\nDecrypted message:", dec_msg)

    print("\nOriginal message:", numberToMsg(dec_msg))

    