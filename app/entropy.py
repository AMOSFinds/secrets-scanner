import math


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    # calculate character distribution
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy