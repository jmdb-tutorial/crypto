# Cryptography I - Overview

## Introduction 

Uses of cryptography:

### Secure messaging

protecting files on disk

These can be seen as the same if Alice is sending a message to herself in the future with disk encryption 

Composed of two parts - 

1. Handshake protocol - exchanging a key (public key cryptography)
2. Record layer - transmit data using a shared secret that gives integrity and confidentiality

Building block is symmetric encryption (point 2 above and first part of course) 

Encryption algorithm is publically known. Never use a proprietary cipher

```
E, D : cyphers.  k : secret key
m, c : plaintext message, ciphertext
```
```
E(k,m) = c  :: encrypt m to c
D(k, c) = m :: decrypt c to m
```

1. Single use keys eg encrypted mail, new key for each email
2. Multiple use keys - eg files on disk require more machinery to make safe

### Core things crypto does is 

Secure key establishment
Secure communication 

But also

Digital signatures
Anonymous communication (mix nets)
Anonymous digital cash
Elections
Private auctions

*“Thm”: Anything that can be done with a trusted authority can also be done without*

A generalisation of private auctions is secure multiparty communication

Privately outsourced computation (eg if could get google to execute a search on encrypted query)

Zero knowledge (proof of knowledge)

Eg N = p.r  - can prove that know p and r

### Cryptography is a rigorous science:

1. Precisely specify the threat model
2. Propose a constructions
3. Prove that breaking the construction under the given threat model will solve an underlying “hard” problem (eg factorising two big prime numbers


## History of Cryptography

Roman era

1. Symmetric ciphers - where the key is the same on encryption (E) and decryption (D)

Substitution ciphers - the key is a substitution table of the letters

Ceaser cipher (shift by 3, has no key) related to substitution cypher but the key is fixed (shift the letter by 3 so a becomes b

This is not a cipher because the key is fixed.

For a substitution ciphers - the key space is 26! Or 2^88 - which is 88 bits which is 2 ^ 88 because a bit can be 0 or 1 which is 2

Keyspace is fine in terms of key space but is very insecure.

Can break a substitution cipher by using frequency of English letters.

Because e is the most common letter, the letter with the largest occurrence in the cipher text will be e

Then can do 
“E”: 12.7%
“T”: 9.1%
“A”: 8.1%

But rest of letters are similar

Then can use digrams (combinations of 2 letters)

“He”, “an”, “in”

Then trigrams.

So never use a substitution cipher

2. Vigener cipher (Renaissance  16th century Rome) (VIJINEER)


Make a key and then repeat it over the message

Then add the letters of the key to the letters of the message mod 26

```
k = C R Y P T O C R Y P T O C R Y P T
m = W H A T A N I C E D A Y T O D A Y
-------------------------------------
c = Z Z Z J U C L U D T U N W G C Q S
```
def add_two_letters (a b):
    new_letter = (index_of_letter(a) + index_of_letter(b)) % 26
    return letter_from_index(new_letter)

Take each letter as a number from 1-26 add them together mod 26 and then you get the encrypted version

See [vigener_cipher.py](./vigener_cipher.py)







Reading:

https://en.wikibooks.org/wiki/High_School_Mathematics_Extensions/Discrete_Probability

http://toc.cryptotextbook.net/home

http://shoup.net/ntb/ntb-v2.pdf


