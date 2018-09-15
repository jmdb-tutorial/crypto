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



