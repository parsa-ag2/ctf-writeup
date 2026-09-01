import re

text = open("word.txt").read()


words = re.findall(r'\b[ab]+\b', text)


bits = ''.join('1' if 'b' in word else '0' for word in words)


flag = ''.join(
    chr(int(bits[i:i+8], 2))
    for i in range(0, len(bits) - 7, 8)
)

print("Number of words:", len(words))
print("Number of bits:", len(bits))
print("Flag:", flag)