#!/usr/bin/python

import binascii

msgs = []

msgs.append("315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e")

msgs.append("234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f")

msgs.append("32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb")

msgs.append("32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa")

msgs.append("3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070")

msgs.append("32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4")

msgs.append("32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce")

msgs.append("315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3")

msgs.append("271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027")

msgs.append("466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83")

target_message = "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"


def xor_bytes(bytes0, bytes1):
    output = []
    for i in (range (0, len(bytes0))):
        output.append(bytes0[i] ^ bytes1[i])
    return output


def as_bytes(msgs, trimlen):
    output = []
    for m in msgs:
        output.append(bytearray.fromhex(m)[:trimlen])
    return output


def display_messages(msgs):
    print "number of test messages: %d" % len(msgs)

    i = 0
    for m in msgs:
        s = msgs[i][:50]
        print "m[%d] : length=%d\n%s" % (i, len(msgs[i]), s)

        mbytes = bytearray.fromhex(s)

        sbytes = ""
        for b in mbytes:
            sbytes = sbytes + str(b) + " "

        print sbytes
        i = i + 1

def bytes_as_str(msg):
    sbytes = ""
    for b in msg:
        sbytes = sbytes + "%3d" % b + " "
    return sbytes
        

def display_message(label="", msg=""):
    sbytes = bytes_as_str(msg)
    print(label)
    print(sbytes)


def extract_key(msg1, msg2):
    return xor_bytes(msg1, msg2)


def string_to_asc(s):
    output = []
    for c in s:
        output.append(ord(c))
    return output


def assignment_1():
    print "Going to try to decrypt some messages..."
    # display_messages(msgs)

    target_as_bytes = bytearray.fromhex(target_message)
    display_message("target : len=%d" % len(target_as_bytes), target_as_bytes)

    print "\nGoing to try xoring them"
    msgs_as_bytes = as_bytes(msgs, len(target_as_bytes))
    i = 0
    for m in msgs_as_bytes:
        display_message("Message %d: len=%d :" % (i, len(m)), m)
        i = i + 1
    display_message("key_1", extract_key(msgs_as_bytes[0], msgs_as_bytes[1]))
    display_message("key_2", extract_key(msgs_as_bytes[0], msgs_as_bytes[2]))
    display_message("key_3", extract_key(msgs_as_bytes[0], msgs_as_bytes[3]))

    space_as_bytes = string_to_asc("    ")
    a_as_bytes = string_to_asc("1234")

    display_message("key_spaces", extract_key(space_as_bytes, a_as_bytes))
                    
                
#    for m in msgs


    
    
def table_of_xors():
    array_of_chars = [32] + range(97, 122)
    
    output = "    " + " ".join([" " + chr(x) for x in array_of_chars]) + "\n"
    
    for x in array_of_chars:
        output = output + chr(x) + " : "
        for y in array_of_chars:
            output = output + "%2d " % (x ^ y)
        output = output + "\n"

    return output

print table_of_xors()

target_as_bytes = bytearray.fromhex(target_message)
display_message("target : len=%d" % len(target_as_bytes), target_as_bytes)

msgs_as_bytes = as_bytes(msgs, len(target_as_bytes))

msg1 = msgs_as_bytes[0]
msg2 = msgs_as_bytes[1]


s1 = bytes_as_str(msg1[:20])
s2 = bytes_as_str(msg2[:20])
xor12 = xor_bytes(msg1, msg2)

s3 = bytes_as_str(xor12[:20])

print "msg1: " + s1 +"\nmsg2: " + s2 + "\nxor:  " + s3

assignment_1()

# The XOR of two characters in the ciphertext will be the same as the xor of the original characters.
# E.g. Take the letter 'a' (ord = 97) and the letter 'k' (ord = 104) the xor is 9
# Now xor both of them with some random number (say 174) and you get
# 207 and 198
# 198 ^ 207 is 9
# (a xor k) xor (b xor k) = a xor b for any two letters 

# Algorithm 1: XOR the known plaintext with the known cipher text and you will recover the key
# Then you can XOR the target plaintext with the key and get the target cipher text
# Algorithm 2, take the XOR of the letters you want to change and the original and then XOR the ciphertext
# For example:
# "attack at dawn" in ascii numbers is:
# [97 116 116 97 99 107 32 97 116 32 100 97 119 110]
# "dawn" is [100, 97, 119, 110] (can do ord('d') for each letter)
# "attack at dusk" is
# 97 116 116 97 99 107 32 97 116 32 100 117 115 107
# "dusk" is [100, 117, 115, 107]
# xor of "u" and "a" is 117 ^ 97 which is 20.
# The ciphertext is
# 108 115 213 36 10 148 140 134 152 27 194 148 129 77
# E("dawn") is [194, 148, 129, 77)
# if we xor the ciphertext of the "a" (148) with 20 we get:
# 128
# If we also xor ciphertext of "a" (148) with ord("a") (97) we get:
# 245, which is the key for that position.
# SO to loop back, we could also encrypt the character "u" (117) with the key (245)
# 245^117 = 128
# So either way the target ciphertext for this character is 128
# Target ciphertext is:
# 108 115 213 36 10 148 140 134 152 27 194 128 133 72
# or in hex:
#
def question_7_quiz():
    known_ct = "6c73d5240a948c86981bc294814d"
    kct_bytes = bytearray.fromhex(known_ct)
    known_pt = "attack at dawn"
    known_pt_bytes = string_to_asc(known_pt)
    target_pt = "attack at dusk"
    target_pt_bytes = string_to_asc(target_pt)

    display_message("Ciphertext as bytes:", kct_bytes)
    display_message("Known plaintext as bytes:", known_pt_bytes)
    display_message("Target plaintext as bytes:", target_pt_bytes)

    key = xor_bytes(kct_bytes, known_pt_bytes)
    display_message("Key derieved from xoring ct and pt:", key)

    target_ct = xor_bytes(key, target_pt_bytes)
    display_message("Target ciphertext: ", target_ct)

    target_ct_hex = binascii.hexlify(bytearray(target_ct))
    print("Target ciphertext as hex string:")
    print(target_ct_hex.decode())


#question_7_quiz()
