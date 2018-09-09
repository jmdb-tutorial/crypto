#!/usr/bin/python

"""
When we want to make a repeating loop of numbers, or a cycle, we can use the modulo operator
this is '%' in python.

e.g. 12 mod 26 would be 12 - it basically gives you the remainder after dividing the first number by the second.

This is very useful as it can limit a set of numbers to within a certain range. However its is slightly confusing
because you may want say

```
[1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6]
```
Lets try this naievely: (dont get confused with the python string interpolation which also uses '%'!)

"""

def mod_list_1():
    for x in range(1, 13):
        x_mod_6 = x % 6
        print "x = %02d, x mod 6 = %d " % (x, x_mod_6)

print "Output from mod_list_1() ..."
mod_list_1()
print ""
        
"""
The problem is that the numbers go

```
[1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5, 0]
```

Because what the modulo function is doing is returning the *remainder*.


What we want is the last number to be 6. We can see from the sequence that the mod of 5 is 5 so if we add one to that it would be 6...

"""

def mod_list_2():
    for x in range(1, 13):
        result = (x % 6) + 1
        print "x = %02d, x mod 6 = %d " % (x, result)

print "Output from mod_list_2() ..."
mod_list_2()
print ""

"""
This is not very useful but we can see we now get the number 6 in our sequence.

So what could be done is to shift everything down one. What we see in the above sequence is that for `x = 6`, `x mod 6 = 1` but that `x mod 5` gives the correct result, so what if we just take 1 from 6?

Also we need to know that `0 mod n = 0`. Which means that when we calculate for `x = 1` we will actually do `0 mod 6` which will be 0 and then we will add one to it to make it `1` again.
"""

def mod_list_3():
    for x in range(1, 13):
        result = ((x - 1)  % 6) + 1
        print "x = %02d, x mod 6 = %d " % (x, result)

print "Output from mod_list_3()"
mod_list_3()
print ""

"""
Hey presto and we have our list working.
"""



                    
    
