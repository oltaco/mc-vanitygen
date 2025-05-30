mc-vanitygen - MeshCore Vanity Key Generator
--

Tired of your boring cryptographically secure public key? Looking for something potentially less secure and more eye catching?

Waste time, waste power, impress no one. But hey, at least your pubkey ends in **`1337c0d3`**!

If you want your pubkey to start with **`deadbeef`** and your room to be warmed by CPU cycles then mc-vanitygen is the tool for you!

- Is this secure? Who knows.
- Should you care? Probably. *\*shrug\**
- Is it stupid? Absolutely yes.
- Will your key look metal as hell? Without a doubt.

Usage
--
`$ ./mc-vanitygen [options] <hex_pattern1> [hex_patternX] ...`

Examples
--
```
# Prefix of c0c0a
./mc-vanitygen c0c0a

# Prefix *and* suffix of 12
./mc-vanitygen --both 12

# Suffix of abc *or* def, continuous search
./mc-vanitygen -s -c abc def

# Any combination of b0b / d1d / c0f in suffix or prefix or both, continously
./mc-vanitygen -e -c b0b d1d c0f
```

