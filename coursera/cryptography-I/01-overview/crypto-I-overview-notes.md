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


Take each letter as a number from 1-26 add them together mod 26 and then you get the encrypted version

See [vigener_cipher.py](./vigener_cipher.py)

As background its also worth looking at how to calculate modulo cycles in code
([modulo.py](./modulo.py))










Reading:

https://en.wikibooks.org/wiki/High_School_Mathematics_Extensions/Discrete_Probability

http://toc.cryptotextbook.net/home

http://shoup.net/ntb/ntb-v2.pdf





## Discrete probability


### Basics
Background maths concepts:

Real numbers : [https://en.wikipedia.org/wiki/Real_number](https://en.wikipedia.org/wiki/Real_number)



Set notation [https://en.wikipedia.org/wiki/Set_notation](https://en.wikipedia.org/wiki/Set_notation)

Coordinate Vectors [https://en.wikipedia.org/wiki/Coordinate_vector](https://en.wikipedia.org/wiki/Coordinate_vector)


Vector notation [https://en.wikipedia.org/wiki/Vector_notation](https://en.wikipedia.org/wiki/Vector_notation)

Field [https://en.wikipedia.org/wiki/Field_(mathematics)](https://en.wikipedia.org/wiki/Field_(mathematics))

A field is a set of numbers. 

R is used to denote the set of Real numbers

R^2 would be the vector space of all coordinates (a,b) 

R^8 would be the vector space of all coordinates ( a, b, c, d, e, f, g, h )

Inverted A symbol means "For all"

the finite set of bits is always {0, 0}^n 

For example {0, 1}^2 = { 00, 01, 10, 11 } - bascially all the combinations

The finite set of {0, 1}^3 = { 000, 001, 010, 011, 100, 101, 110, 111 }

Whic would represent a vector space of R^8 because there are 8 coordinates

In the course he calls this a "vector of dimension eight, there will be, there are eight strings of 3-bits. As a result basically the entire distribution is captured by this vector of eight real numbers, in the range of all zero or one.

He writes this as E|R^8

where E is the "in set of" symbol" which is usually curved

See [https://en.wikipedia.org/wiki/Vertical_bar](https://en.wikipedia.org/wiki/Vertical_bar) for uses of the bar symbol

But doesnt explain the use here which is to state "eight real numbers in the range od all zero or one.

Importantly remember that the vector is of the probability distributions, i.e. its really:

( P(000), P(001), ..., P(111) )

Where P is actually then something like:

{ 1/2, 1/4, 1/4, ..., 1/8 }

This is the set of 8 real numbers in the range zero to one.

see also [http://www.sosmath.com/algebra/inequalities/ineq02/ineq02.html](http://www.sosmath.com/algebra/inequalities/ineq02/ineq02.html)

An interval that includes its number is denoted with square brakets, e.g. [0, 1] means the interval between 0 and 1, *including* zero and one.

So when he writes "in" [0, 1] it means in the interval of 0 and 1


Subset of the whole universe of probability is called an *event* and can then talk about the probability of that event P(A)

Events are denoted by A


So the size of the U with {0,1}^8 in it is 256 because its 2^8 

So the probability of a subset of things happening can be expressed and is called an event, for example whats the probability that the least significant bits of one of the strings is "11".

We can then talk about the Union bound of two events - so what is the probability that either A1 or A2 occurs.

We can say that the union of the two probabilities wil be less than or equal to the sum of the probabilities. if the two events are disjoint, i.e. do not intersect, then the union of the probabilities is exactly equal to the sum of the probabilities.

### Random Variables

- The uniform random variable

### Randomized algorithms

As opposed to deterministic where the same output is always produced.

But the algorithm specifies a set Random variable which is a set of all the possible outputs of the random agorithim


### Independence

Are independent if the fact that event A happens tells you nothing about event B

Formally this is the case if the probablity of [A and B] = Pr[A] * Pr[B] - i.e. multiplied


Ie if you think about two dice, the probability of one being 3 and the other being 5 would be 1/6 * 1/6 which would be 1/36 which would be the sum of the probabilities which would be 1/3 because you have two chances of the event happening.

**Example**

Take a Universe U = {0,1} ^2  = a universe of two bit strings = {00 01 10 11} and select a random element (r) from there with uniform probability

Define random variables X and Y as least significant bit and most significant bit lsb(r) and msb (r)

The probability of [X=0 and Y=0] = Pr[ r=00] = 1/4 (there are 4 elements and so its 1 out of 4

The probability of X=0 is 1/2 and Y=0 is also 1/2 because for each one there are two out of the elements which could match the random variable.

1/2 * 1/2 = 1/4 and therefore the Pr[A and B] = Pr[A] * Pr[B]

### An important property of XOR

Addition of the bits modulo 2

Theorum: If you take a random variable Y over {0,1}^n with some unknown distribution and an *independent* random variable with a uniform distribution over {0,1}^n then a random variable of XOR of these will also have a uniform distribution.


Proof:

|Y|Pr|
|-|--|
|0|P0|
|1|P1|

|X|Pr |
|-|---|
|0|1/2|
|1|1/2|

Because X is uniform over two bits then its probability is known to be 1/2

Because X is independent, we know that the probability of X and Y is multiplied of the two probabilities:

P0 * 1/2 = P0/2

|Y|X|Pr  |
|-|-|----|
|0|0|P0/2|
|0|1|P0/2|
|1|0|P1/2|
|1|1|P1/2|

So now we know that Z which would be the XOR would result in eithee (X, Y) == (0, 0) or (X, Y) = (1, 1) because:

|Y|X|Y XOR X|
|-|-|-------|
|0|0|0| 
|0|1|1|
|1|0|1|
|1|1|0| 

SO now take the question, what is the probability that Z is 0:

Becaus its an OR, i.e. its the probability of either (0,0) OR (1, 1) then we can simply SUM the probabilities to get the probability of Z

P0/2 + P1/2

Which is P0 + P1

Now because we know that P0 and P1 are from a probability distribution, we know that they must add up to 1, so :

it becomes 1/2.

If Pr[ Z=0 ] is 1/2 then it follows that Pr [ Z=1 ] Is also 1/2 because they too must add up to 0

In general:

Pr[ A or B ] = Pr[A] + Pr[B], if they are disjoint.

### The birthday paradox

Basically if you have a set of independentaly identiaclly distributed random variables, then if you sample 

n = 1.2 * |U|^1/2 

where |U| is the size of the elements whichi is basically saying the square root of the number of elements, then the probability that there exists two samples will be equal to each other is greater than 1/2

inverted E means "there exists"

example, lets say there is a 128 but string {0,1}^128 U = 2^128 so after sampling about 2^64 random messages from U, you are likely to find 2 sampled messages that are the same.

Need to know a bit of exponents maths: (https://www.dummies.com/education/math/algebra/how-to-convert-square-roots-to-exponents/)

Basically the nth root of a^m is a^(m/n)

So sqrt (2 root of a^128 is a^(128/2) = a^64,p here given that a is 2 because its the number of bits which is 0 or 1.

if U = {0, 1}^128, |U| = 2 ^ 128

sqrt(2^128) = 2^64



Called the birthday paradox because imagine the samples are peoples birthdays, how many people do you need to sample before you find two people with the same birthday

365 1.2* sqrt(365) = about 24 random people.

So only need 24 people. 

Peoples birthdays ar enot uniformly distributed.

Probability of getting two samples the same goes up very quickly to 1 as soon as you go above the sqrt(|U|)





## Information theoretic security and the one time pad

def: a cipher is dephined over (K, M C)

(Script K, M, C)

IS defined over the set of all possible keys (keyspace)
all possible messages and all possible messages
All possible cipher texts

is a pair of "efficient" algorithms (E, D)

E: K * M -> C
D: K*C -> M

need to satisfy the consitency equation, correctness.

D(K, E(k, m)) = m

efficient is in quotes because it means different things to different people - if you are theoretical, must run in polynomial time [http://mathworld.wolfram.com/PolynomialTime.html](http://mathworld.wolfram.com/PolynomialTime.html) number of steps required to complete the algorithm for a given input is O(n^k) where n is complexity of the input and k is some non negative integer.

https://stackoverflow.com/questions/4317414/polynomial-time-and-exponential-time

http://bigocheatsheet.com/


https://en.wikipedia.org/wiki/Big_O_notation

O is used because it referes to the "order" of the function - its about the growth rate of a function as more complexity (e.g. number of elements gets added. 

O(1) or O(log n) will grow at a very slow and constant rate

O(n) will grow proportionally to n

O(n log n) constant but more rapid rate (straight line)

O(n^2) is quadratic time, a special case of polynomial time

O(n^k) polynomial time

O(k^n) exponential time 

if more practically inclined, rather choose some measure of time. like must run in less than a minute.

E is often randomised, D is always deterministic

### First example of a secure cipher

M = C = {0,1}^n

K = {0,1}^n

message space is the same as the ciphertext space which is all {0,1}^n binary strings

key is a random bit string as long as the message

cipher text is xor of key and message

e.g.

```
msg: 0 1 1 0 1 1 1
k  : 1 0 1 1 0 0 1  XOR
c  : 1 1 0 1 1 1 0
```

To decrypt, just XOR the key and the ciphertext

Just need to satisfy consistency requirement:

So

D(k, E(k, m)) = D(k, k xor m) = k xor ( k xor m ) 

xor is addition modulo 2, and as addition is associative, so is xor.

xor is associative (doesnt matter what order the operations are in)  so can change the order of the parenthesis as long as the sequence of operations stays the same:

[https://en.wikipedia.org/wiki/Associative_property](https://en.wikipedia.org/wiki/Associative_property)

so can rewrite the above as

(k xor k) xor m

We know that k xor k is always 0

1 1 : 0
0 0 : 0

so we are left with 

0 xor m

and zero xor anything leaves it alone:

0 1 : 1
0 0 : 0

So 0 xor m = m

So we can show that the one time pad is a cipher (it satisfies the consistency constraint). but doesnt say anything about the security of it

One time pad is super fast but difficult to use in practice because the key is as long as the message

And then also needs to transmit the key to bob that is as long as the messsage - if alice already has a secure mechanism to transmit this to bob, she might aswell use the same method to transmit the message!

One time pad is difficult to use in practice although the idea is useful.


Is OTP secure? What is a good cipher?

Basic Idea From infromation theoretixc security (Claude Shannon 1949) [https://en.wikipedia.org/wiki/Information-theoretic_security](https://en.wikipedia.org/wiki/Information-theoretic_security)


Communication theory of secrecy systems

Shannon examines 1 time pad.

Basic Idea: if you only see the cypher text, it should reveal no "information about the plaintext.

DEF: A cypher (E, D) over (K, M, C) has perfect secrecy if

for every 2 messages (m0 and m1) in the message space that have the same length

and for every cypher in the cipher space.


the probability of encrpting m0 = c is exactly the same as the probability of encrypting m1 and getting c

Pr[E(k, m0) = c] = Pr[E(k, m1) = c]

                                 R
where the k is uniform in K  k <--- K means that k is sampled with a uniform distribution from the keyspace

this works because if an attacker just intercepts the cipher text, then the probability that the cypher text came from m0 is exactly the same as if it came from m1 os if all we have is the cipher text, have no information about the message

=> Given a particular cipher text, cant tell if the message was encrypted from m0, m1 or m2 or m3

=> The most powerful adversary learns nothing about the plaintext from the ciphertext

=> there is no CT only attack (but other attacks may be possible)

Lemma: OTP has perfect secrecy
Proof: 

the probability of :

Pr[E(k, m) = c] = #keys such that E(k, m) = C / |K|  (number of elements in K

if the number of keyss in k is a constant then the probability has to be constant and so therefor for any two messages probability will be the same

Because its just using xor, 

K xor m = c --> k = m xor c

So the key has to be dependant on the message - i.e. the key is an xor of the cipher text and the message

this holds for all messages and cipher texts.

For the OTP there is no CT only attack!

but there are other attacks that are possible.

Having perfect secrecy does not mean OTP is secure to use.

Problem is that OPT has same length of key as the message.


Are there other ciphers with perfect secrecy that need shorter keys?

Shannon then prooved that to have perfect secrecy, |K| >= |M|

i.e. the length of keys must be at least equal to the length of messages, infact the OTP makes this an equality so its actually the most efficient algorithm of this

So the result is that perfect secrecy means that its not practical to use these.





## Stream ciphers

Replace "random key" with "psuedorandom" key

i.e. can generate a key of arbitrary length from an initial key of a fixed length

its using a function called G which takes a {0,1}^s string of bits and generates {0,1}^n output where n>>s (significantly bigger, like bytes to GB)

G must be "efficiently" computable.

The resulting sequence should be indistinguishable from random number.

Stream cipher cannot haver perfect secrecy because the key is shorter than the message

- Need a different definition of security.

- Security will depend on the the specific Pseudo random number generator

PRG must be unpredictable. 

because if you happen to know the first parts of a message, for example if the message was like an email that always began with

from:

Could xor the message with the known text and then predict the rest of the key.

Even if you can predict just the next bit after a sequence it would not be enough.

### What does it mean for a PRG to be unpredictable

Say that G: K -> {0, 1}^n is predictable

if there exists an efficitln algorithm where given an algorthim that takes a random key 

Can return the next bit with greater than 1/2 + Epsilon

for some non-neglible value of epsilon - e >= 1/2^30

DEF: prg is unpredictable if it is not predictable

For all I : no "eff" adv can predict bit (n+1) for a "non-neg" epsilon


e.g. a generator that for all K  XOR(G(k)) = 1 is predictable given the first n bits - because if I have a set of bits the next one will be whatever it takes to XOR to 1

### Weak PRGs - DO NOT USE FOR CRYPTO!

Linear congruential generator with params a, b, p

r[0] = seed 

iteratively compute

a.r[i-1]+b mod p

Very easy to predict! just given a few output examples can predict 

glibc random() never ever use built in random()  from clib because it doesnt produce cryptographically strong randoms i.e. those that are not easy to predict

e.g. kerberos 4 used random and got bitten

### Negligible and non-negligible values 

- in practice epsilon is a scalar [https://en.wikipedia.org/wiki/Scalar_(mathematics)](https://en.wikipedia.org/wiki/Scalar_(mathematics))

and non negligible is over 1/2^30 - 1gb of data is about 2^32. 

an event that is 1/2^30 is non negligible because it is likely to happen within 1GB of data

negligible would be less than 1/2^80 is an event that is not going to happen over the length of life of the key and so is non negligible

In theory of cryptography.

We dont talk about these as scalar values but as functions

if basically something is often bigger tahan a certain polynomial.

non-negligible greater than epsilon(lambda) >= 1 / lambda ^ d

or neglible is less than 1/ lamda ^ d

if have epsilon(lambda) = 1 / 2 ^ lambda

this would be negligible becaause for any constant d in the main equation, this will be less.

so for example

1/2^lambda would be less than 1/lambda^d

d is the polynomial of the lambda

however 1/ lambda ^ 1000 would be non-negligible

if set d to 10,000 then this one is clearly greater because it is only to the power 1000


If had a function that switched to 1/2^lamda for odds and 1/lambda^1000 for even, it would still be non-ngligible because it would be happening a lot and be enough to be bigger than the polynomial eventually

## Attacks on otp and stream cyphers

Using a one time pad twice!

Never use a stream cipher key more than once!!!

c1 <- m1 xor PRG(k)
c2 <- m2 xor PRG(k)

eavesdropper does:

c1 xor c2  (the PRG's cancel out and you are left with m1 xor m2)

k : 1 1 0 1
m1: 0 1 1 0
m2: 1 0 0 1

c1 = 1 0 1 1
c2 = 0 1 0 0

c1 xor c2: 1 1 1 1

m1 xor m2: 1 1 1 1

### Real world examples

#### Two time pad attack

Project venona (1941-1946) russians = human would right down the throws of the dice which were written down. Was laborious and so they used them more than once.

We able to decrypt 3000 plaintexts.

Windows NT point to point transfer protocol MS-PPTP

CLient and server both share a key

Two parallel lines || means concatenation

client and server are sending messages m1, m2, m3 and xored with the key, but the server is also doing this

Never use the same key to encrypt traffic in both directions

Use two keys one from server to client and one from client to server.

also 802.11b WEP concatenate  IV with a long term key. IV is a variabl number that changes with each frame,  But IV is only 24 bits so after about 2^24 or 16m frames it will recycle so effectively you will be have messages with two keys.

Further, on some 802.11 card, when you turn off the power, IV resets to 0 so you are going to end up with the same pad for different messages.

Avoid related keys:

key for frame #1 (1 || k)
              #2 (2 || k) 
              
all have same suffix of 104 bits

for the PRG that is used in WEP (RC4) Fluhrer mantin and shamir in 2001 that after about 10^6 or 1 million frames, you can recover the secret key.

All have to do is listen to about 1 million frames to recover the orignial key

these days only 40,0000 frames are sufficient - in a matter of minutes can recover the secret key of the WEP network.

What should they have done?

Treated m1, m2 m3 as one long stream and then xored them as a giant stream

or, if want a different key for each frame, put the long term key through a PRG and generate a long key and then use the first segment for frame 1 second for frame 2 etc

Final example is in disk encryption.

File gets broken into blocks and then get encrypted.

if say just changed the first part from "to bob" to "to eve" - an attacker can see that there is only one segment that is different. So even though the attacker doesnt know what the contents are, cna see exactly where the change was made. 

Usually a bad idea for stream ciphers to be used for disk encryption.

Never use a stream cipher key more than once!

Network traffic - client->server one stream with one key
                  server->client another stream with a different key
                  
Disk encryption dont use stream ciphers.



#### No integrity

m gets encrypted (xor k)

But then gets modified with xor p

now when it gets decrypted :
k xor ((m xor k) xor p)

(k xor k) xor (m xor p)

k xor k cancels out the k and so you are left with a very specific modification of the original message

Modifications are undetected and have predictable impact on the plaintext

e.g. say an attacker knows the message starts with "From: Bob"

can mutate it 


B  o  b    E  v  e   Bob xor Eve
62 6F 62   45 76 65  01 19 07

```
>>> hex(0x42 ^ 0x45)
'0x7'
>>> hex(0x6f ^ 0x76)
'0x19'
>>> hex(0x63 ^ 0x65)
'0x6'
```

in python you can do this like "65".decode("hex") = e

Can xor them like this:

0x65 ^ 0x62

or turn them into binary representations like this:

bin(0x65)


65 : 0b1100101
62 : 0b1100010
7  : 0b000 111

```
>>> ord('e')
101
>>> hex(ord('e'))
'0x65'
```

```
>>> hex(0x42 ^ 0x07)
'0x45'
>>> hex(0x6f ^ 0x19)
'0x76'
>>> hex(0x62 ^ 0x07)
'0x65'
```

Property called "malleability" one time pad is known as "malleable" OTP has no integrity and is completely insecure against modifications.





## Stream ciphers that are used in practice

Not really supposed to be used in modern systems but are still around so need to know about them

### RC4 1987

- Takes a variabl seed
- expands it into 2048 bits and then runs a generator generating 1 byte per round
- Used in HTTPS and WEP - google uses it in its https 

Over years, weaknesses have been found and so its now reccommended to use more modern ones

Weaknesses:

1. Bias in initial output:

 if you look at the second byte then the Pr[ 2nd byte = 0] should be 1/256 as there are 256 possible values for the first byte [0-255]
 Infact, the probability is 2/256 
 
 First and third bytes are also biased - if you are going to use RC4 need to ignore first 256 bytes. Start using output of generator from byte 257
 
2. Probability of seeing two byted together of [0, 0] should be  1/256^2 but RC4 is biased and its actually 1/256^2 + 1/256^3 - this only happens after several gigabytes of data but nevertheless is something that can be used to predict the generastro and can definitely be used to distinguish from a truly random sequence

The fact that 0,0 appears more often than it should

3. Related key attack

If use keys that asre closely related to each other, like with WEP can recover the root key

### CSS Content scrambling system (badly broken)

Used in DVD encryption
Badly broken and can easily be used to decrypt encrypted DVDs

Popular with hardware encryption because it doesnt require too many transistors

Uses a linear feedback shift register (LFSR)

Have a set of cells of 1 bit each. Take some cells called "taps" and then these feed into an XOR - every clock cycle the register shifts, the right hand bit falls off and the left hand bit is replaced by the output of the XOR

Seed is the initial state of the LFSR

DVD encryption uses two of them

GSM encryption - 3 LFSRS

Bluetooth - 4 LFSRS

All of these as badly broken so shouldnt be used but are now stuck in hardware so its hard to remove them.

How CSS works

seed = 5 bytes = 40 bits (limited due to export regulations of US)

2 LFSRs 17 bit and 25 bit

first one is initialised by 1 concatenated with the first two bytes of the key

the second one is 1 || with last 3 bytes of the key

Then the lsfrs are run for 8 cycles, generating each 8 bits of outpu then put through an adder (addition mod 256) also adds the carry from the previous block (0 or 1)

One byte is generated per round and then used to be xored with the byte of the movie that is being encrypted.

Turns out is easy to break in 2^17 time

If you happen to know the first 20 bytesd of the streanm, you can xor it and get the first 20 bytes of the CSS generator

So then can brute force calculate every possible combination of the LFSR and generate first 20 bytes from it

Because we have the ACTUAL bytes from the CSS we can subtract these from the 20 bytes generated and get what was the output from the other, 25 bit LFSR

TUrns out that its easy to tell if a string of bytes came from a 25 byt LFSR or not - so can easily test wether or not we got the right initial state or not.

Keep doing until we get a set of bytes that are the right outputs

Once we have this we have the initial state of both the LFSRs and can then just run the algorithm.

MAny open source systems use this method to decrypt encrypted CSS data

- Homework assignment to look at breaking stream ciphers




###  Modern stream ciphers = eStream (2008)

eStream qualified 5 different srtream ciphers.

Going to present 1 - parameters of these are different.

PRG: {0, 1}^s xx R -> {0,1}^n

n is much bigger than s

Nonce: a value that is never going to repeat for the same key

Now have an encryption algorithm that looks like this:


E(k, m ; r) = m xor PRG(k ; r)

THe pair (k, r) is never used more than once

Can reuse the key because the nonce makes the pair unique

Example Salsa20 - used for bothe Software and hardware

Designed to be easy in software and hardware

Takes either 128 or 256 bit seeds - going to explain 128 Max size it can go to is 2^73 bits

and a 64 bit nonce

Salsa20(k ; r) := H(k, (r, 0)) || H(k, (r, 1)) ||

H is a function that generates the sequence

make 64bytes

4 bytes T0 - fixed constant
16 bytes K - key
4 bytes T1 - another constant
4bytes r - nonce
8 bytes i - index
4 bytes T2
16 bytes K - again
4 bytes T3

Apply a function h - is an invertible function designed to be fast on x86 easy to implement because it has this SSE2 instruction set which makes this very efficient


given 64 bits generates another 64 bits

DOes this 10 times

then do an addition of a word by word (4 bytes at a time to the end of the original 64 bytes

This can be repeated by iuncrementing the counter and will give you a pseudorandom number as long as you need it to be

Seems to be unpredictable and safe to use

eStream has 5 like this - salsa is most elegant

2.2GHx machine
            Speed (MB/seC)
RC4         126
Salsa20/12  643
Sosemanuk   727







## PRG Security Definitions

### Definition Of a Psuedo random Generator

Let G : K -> {0,1}^n 

A generator G over a keyspace K

What does it mean for the output of the generator to be indistinguishable from random?

[ k <-R- K, output G(k) ]

Take a random key k from the keyspace, and output G(k) generate output from k

it should be "indistinguishable" from the random output of 

[ r <-R- {0,1}^n, output r ]

which means select r at random from the total space of {0,1}^n byte strings


How can this be when the psuedorandom generator of G is so small, the number of potential things that can be generated is much smaller than  the total space.

However we are trying to show that one of the selections from the space of G would be indistinguishable from a selection from the total space

### Statistical Tests

Marked by A

A(x) as an input an n bit string and outputs either "0" or "1" decides wether it looks random or not. can do whatever it wants, 

e.g. for a random string, the number of zeros and ones should be roughly the same:

(1) So A(x) = 1 iFF (if and only if)  | #0(x) - #1(x)| <= 10 * sqrt(n)  (number of zeros in x)

(2) A(x) = 1 iFF | #00(x) - n/4 | <= 10 * sqrt(n) - the chances of seeing two 00 in a row is 1/4 because its 1/2 * 1/2 - probability of getting zero twice

All zero string will not look random


(3) A(x) = 1 iFF maximum-run-of-0(x) <= 10 * log_2(n) - if give this the string of all 1's it will think its random

expect in a random string to be roughly the length of log(n)


Stat tests dont have to be right and can do whatever they want.

In the old days, the way you would see if something was random was to apply a fixed set of stat tests.

### Advantage

How do we define wether a statistical test is good or not:

Define Adv_PRG[ A, G ] = | Pr      [A(G(k)) = 1 - Pr            [ A(r) = 1 ] |  
                         | k<-R-K                 r<-R-{0,1}^n               |

 - the result of this as both are probabilitiewill always be in the range [0, 1]
 
 If Adv is close to 1 -> it means that it would be behaving very differently with the PRG  than it did with the random one and so the test was able to distriguish from random and so broke the generator.
 
 If Adv is close to 0 -> means that A cannot distringiush from random
 
 Silly example - if have a s.t. A(x) = 0 - if the statistical test outputs zero whatever you give it. So the Pr that it outputs 1 is 0, the same for the random input and so 0 -0 = 0 and the advantage is zeor
 
 
 Another example:
 
 Have a generator 
 
 G : K -> {0,1}^n satisfies msb(G(k)) = 1 for 2/3 of the keys in K (msb = most significant bit - starts with)
 
 A(x) as:
 
 if [ msb(x) = 1 ] output "1" else output "0"
 
 
 THen Adv_PRG [A, G] = | Pr[A(G(k))=1] - Pr[A(r)=1] | = 1/6 
 
 Because the chance of producing a 1 is 2/3 of the keys and so probability of A(G(k)) being equal to 1 is 2/3, for the random distribution it will be 1/2 because its just the prob of getting either a zero or 1 (1/2)
 
 2/3 - 1/2 = 4/6 - 3/6 = 1/6
 
 
1/6 is non negligible - quite a large number. 

A breaks generator G with adv 1/6


### Secure PRGs : Crypto Definition

G is a secure PRG if

For ALl (inverted A) "Efficient" stat. tests, A:


Adv_prg[A,G] is "negligible"

ITs secure if ALL efficient s.t. adv is negligible.


Restriction of efficient is nescessary - if we ask that ALL s.t. then the definition would be unsatisfiable:

*PUZZLE* leave to think about why this is the case


So can we construct a generator and proove that there is a secure PRG?

Answer is UNKNOWN!! - if you could proove that a generator is pure, then would also proove that P is not equal to NP - if could proove that a particular prg was secuer, woudl imply that P not equal to NP

*PUZZLE* if P is equal to NP its very easy to show that there are no secure prgs so if you can show me that a PRG is secure then it means P cannot be equal to NP which tells you that there cant be any because that would be very hard / "impossible"

If we can;t rigourously proove its secure, do have a lot of options.


### Implications : A secure PRG is unpredicatable

Given a prefix of the generator, its is impossible to predict the next bit.

Start with the opposite - if a PRG is predictable, it is therefore insecure


Define an algorithm A is able to predict this bit with some extra chance than 1/2 which would be just guessing, if given the first i bits of a generator


Pr       [ A(G(k)| 1, ...,m i) = G(k)|i+1 ] = 1/2 + epsilon
k<-R-K

(select k at random from keyspace)
Its 1/2 because even if you just guessed at random youd be right 1/2 of the time. 

Require it to be true for some non-negligible epsilon.

for e.g. 1/1000 - i.e. if the probability of it predicting the next bit is 1/2 + 1/1000 the G is broken because there is an algorithm that cna predict it.

Algorithm A predicts the next bit with a probability of AT LEAST 1/2 + epsilon

Define statistical test B as:
     
     +------------------------------------+
B(x) | if A(X|1, ..., i) = x_i+1 output 1 |
     | else output 0                      |
     +------------------------------------+
     
Give the test a truly random string:

r <-R-{0,1}^n   Pr[ B(r) = 1 ] For a truly random string, next bit is completely independent. So whatever the algorithm is, it will be completely indepentent so whatever it outputs its going to be equal to any random bit which is 1/2

In a random string, its not the output from the first n bits of the generator and therefore A has no information about what the next bit will be and cannot predict it, so it is just guessing which means the probability of it getting it right is 1/2

So it is exactly 1/2 which means it has no information about the string.


In the case of our predictor, A, we know that A is able to predict the next bit with probability 1/2 + epsilon


k <-R-K : Pr [ B(G(k)) = 1 ] > 1/2 + epsilon

By definition of A - it will get it rigth 1/2 + epsilon. It is greater than 1/2 because the A algorithm is bound by 1/2 + epsilon so its gets it right at least 1/2 + epsilon

So the Advantage is :

1/2 - 1/2 + epsilon

So the advantage is > epslilon

Adv_PRG [B, G] > epsilon  (Take the 1/2 away from the inequality > 1/2 + epsilon)

If A is a good predictor then B is a good statistical test and so G must be unsecure,

Contra positive of this is that if G is a secure generator, then there are no statistical tests that can distinguish it from random and therefore there are no good predictor algorithms (A).

If there are no predicting algorithms then it is unpredictable.


### Thm Yao '82 - an unpredictable PRG is secure

Inverse of above, if you can find an unpredictable PRG it must therefore be secure.

If all next-bit predictors cannot distringuish G from random then no statistical test can.

*PUZZLE* proove this theorum yourself

if you have a generator that can compute the first n/2 bits from the last n/2 bits

G is not secure because you can easily build a statistical test that distinguishes it from random.

From Yaos theorum, if it is not secure (i.e. it is distinguishable from random) then Yao says that there must exist a predictor, i.e. it must be predictable - there must be some i where given the first i bits of the generator you can predict the next bit.

So even though can't point to the exact predictor, we can know it is predictable.

A predictor must exist.

### More generally P1 and P2

Generalise the concept of indistinguishability from uniform to be :


Let P1 and P2 - two distributions ove {0,1}^n

Def: se say that P1 and P2 are **computationally indistinguishable** (denoted P1 ~equals_p P2)

So squiglyp - in Polynomial time P1 cannot be distringuished from P2

if  for all "eff" stat. tests A

SO | Pr     [A(x) = 1] - Pr    [A(x) = 1] |  < negligible
   | x<-P1               x<-P2            |

So for any statistical test, the chances of it being 1 for a given x from P1 are close to the chances of it being 1 from the other P2 - by close we mean the difference in the probabilities is less than negligble.

Its advantage of distringuishing between the distributions is negligible if true for all eff st. then the two distributions are computationaly indistringuishable because an efficient algorithm cannot distinguish them.

Can use this notation to define security for a PRG:

a PRG is secure if{ k<-R-K : G(k) } ≈_p uniform( {0,1}^n)
