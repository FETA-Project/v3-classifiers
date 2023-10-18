from functools import lru_cache

import pandas as pd

from . import pygtrie


def create_trie(map_file):
    servicemap = pd.read_csv(map_file)
    servicemap["Domains"] = servicemap["Domains"].map(lambda x: list(map(str.strip, x.split(","))))
    trie = pygtrie.StringTrie(separator=".")
    for _, app in servicemap.iterrows():
        inverted_app_domains = list(map(lambda x: ".".join(reversed(x.split("."))), app.Domains))
        for d in inverted_app_domains:
            is_star = False
            if d.endswith(".*"):
                is_star = True
                d = d[:-2]
            trie[d] = (is_star, app.Tag)
    return trie

@lru_cache(maxsize=10000)
def find_in_trie(d, trie):
    reverse_domain = ".".join(reversed(d.split(".")))
    result = trie.longest_prefix(reverse_domain)
    if result == (None, None):
        return "default-background"
    found_domain = result[0]
    is_star = result[1][0]
    tag = result[1][1]
    if found_domain != reverse_domain and not is_star:
        # happens for domains such as "signaler-pa.clients6.google.com", because "clients6.google.com" is a google-services domain (without star)
        # and "*.google.com" is a domain of the google background class
        return None
    else:
        return tag
