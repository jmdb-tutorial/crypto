#!/usr/bin/python

"""
A Vigener cypher is one where you take a key which is just a word and repeat it multiple times over the message, like this


```
k = C R Y P T O C R Y P T O C R Y P T
m = W H A T A N I C E D A Y T O D A Y
-------------------------------------
c = Z Z Z J U C L U D T U N W G C Q S
```

You take the number of the letter from 1 - 26 and then add the two letters together, modulo 26 (i.e. go back round to 1 again)

Lets break this down. First lets look at the letters in the alphabet


"""
def letters_as_numbers():
    for x in range (1, 27):
        print "%02d : %s" % (x, chr(64+x))


def index_of_letter(letter):
    return ord(letter.upper())-64

def letter_from_index(index):
    return chr(64+index)

def letters():
    for x in range (1, 27):        
        print "%s : %d" % (letter_from_index(x), x)

def add_two_letters (a, b):
    sum_of_two_letters = (index_of_letter(a) + index_of_letter(b))
    new_letter = ((sum_of_two_letters - 1) % 26) + 1
    return letter_from_index(new_letter)


def gen_key(seed, m):
    k = ""
    for i in range (0, len(m)):
        k = k + seed[i % len(seed)]
    return k


        
def E (k, m):
    c = ""
    for i in range (0, len(k)):
        c = c + add_two_letters(k[i], m[i])
    return c
    


