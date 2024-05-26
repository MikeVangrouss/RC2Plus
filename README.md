# RC2+
RC2+ Block cipher encryption source code in C. 8192-bit keys. 128-bit block cipher (like AES) 64 rounds.

RC2+ was released in 2005. It has exactly the same design as RC2 by Ron Rivest but uses 32-bit integers instead of 16-bit integers. It no longer works on 64-bit blocks but on 128-bit blocks like AES.

With RC2+ subkeys are generated by a one-way hash function, representing 8192 bits. Thus attacks against RC2 do not work with RC2+.

All key size limitations have also been removed. The maximum key size is used in RC2+. 
