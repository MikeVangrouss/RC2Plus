/*
 * RC2+ cipher
 * RC2+ by Alexander Pukall 2005
 * 
 * Based on RC2 cipher by Ronald Rivest
 * 
 * 8192-bit keys with 256 * 32-bit subkeys
 * 
 * 128-bit block cipher (like AES) 64 rounds
 * 
 * Uses MD2II hash function to create the 256 subkeys
 * 
 * Code free for all, even for commercial software 
 * No restriction to use. Public Domain 
 * 
 * Compile with gcc: gcc rc2+.c -o rc2+
 * 
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define n1 1024 /* 8192-bit RC2+ key for 256 * 32-bit subkeys */


int x1,x2,i;
unsigned char h2[n1];
unsigned char h1[n1*3];


static void init()
{
    
   x1 = 0;
   x2 = 0;
    for (i = 0; i < n1; i++)
        h2[i] = 0;
    for (i = 0; i < n1; i++)
        h1[i] = 0;
}

static void hashing(unsigned char t1[], size_t b6)
{
    static unsigned char s4[256] = 
    {   13, 199,  11,  67, 237, 193, 164,  77, 115, 184, 141, 222,  73,
        38, 147,  36, 150,  87,  21, 104,  12,  61, 156, 101, 111, 145,
       119,  22, 207,  35, 198,  37, 171, 167,  80,  30, 219,  28, 213,
       121,  86,  29, 214, 242,   6,   4,  89, 162, 110, 175,  19, 157,
         3,  88, 234,  94, 144, 118, 159, 239, 100,  17, 182, 173, 238,
        68,  16,  79, 132,  54, 163,  52,   9,  58,  57,  55, 229, 192,
       170, 226,  56, 231, 187, 158,  70, 224, 233, 245,  26,  47,  32,
        44, 247,   8, 251,  20, 197, 185, 109, 153, 204, 218,  93, 178,
       212, 137,  84, 174,  24, 120, 130, 149,  72, 180, 181, 208, 255,
       189, 152,  18, 143, 176,  60, 249,  27, 227, 128, 139, 243, 253,
        59, 123, 172, 108, 211,  96, 138,  10, 215,  42, 225,  40,  81,
        65,  90,  25,  98, 126, 154,  64, 124, 116, 122,   5,   1, 168,
        83, 190, 131, 191, 244, 240, 235, 177, 155, 228, 125,  66,  43,
       201, 248, 220, 129, 188, 230,  62,  75,  71,  78,  34,  31, 216,
       254, 136,  91, 114, 106,  46, 217, 196,  92, 151, 209, 133,  51,
       236,  33, 252, 127, 179,  69,   7, 183, 105, 146,  97,  39,  15,
       205, 112, 200, 166, 223,  45,  48, 246, 186,  41, 148, 140, 107,
        76,  85,  95, 194, 142,  50,  49, 134,  23, 135, 169, 221, 210,
       203,  63, 165,  82, 161, 202,  53,  14, 206, 232, 103, 102, 195,
       117, 250,  99,   0,  74, 160, 241,   2, 113};
       
    int b1,b2,b3,b4,b5;
   
	b4=0;
    while (b6) {
    
        for (; b6 && x2 < n1; b6--, x2++) {
            b5 = t1[b4++];
            h1[x2 + n1] = b5;
            h1[x2 + (n1*2)] = b5 ^ h1[x2];

            x1 = h2[x2] ^= s4[b5 ^ x1];
        }

        if (x2 == n1)
        {
            b2 = 0;
            x2 = 0;
            
            for (b3 = 0; b3 < (n1+2); b3++) {
                for (b1 = 0; b1 < (n1*3); b1++)
                    b2 = h1[b1] ^= s4[b2];
                b2 = (b2 + b3) % 256;
            }
           }
          }
        }

static void end(unsigned char h4[n1])
{
    
    unsigned char h3[n1];
    int i, n4;
    
    n4 = n1 - x2;
    for (i = 0; i < n4; i++) h3[i] = n4;
    hashing(h3, n4);
    hashing(h2, sizeof(h2));
    for (i = 0; i < n1; i++) h4[i] = h1[i];
}

/**********************************************************************\
* Create 256 * 32-bit subkeys from 1024-byte h4 hash                    *
\**********************************************************************/

void rc2plus_init(unsigned char h4[n1], uint32_t xkey[256])
{

  for (int i=0;i<256;i++)
   {
     xkey[i]=(h4[i*4]<<24)+(h4[(i*4)+1]<<16)+(h4[(i*4)+2]<<8)+(h4[((i*4)+3)]&0xff);
   }
  
}

/**********************************************************************\
* Encrypt an 16-byte block of plaintext using the given key.            *
\**********************************************************************/

void rc2_encrypt(uint32_t plain[4], uint32_t cipher[4], uint32_t xkey[256])
	{
	uint32_t x76, x54, x32, x10;
	int i;

	x76 = plain[3];
	x54 = plain[2];
	x32 = plain[1];
	x10 = plain[0];

	for (i = 0; i < 64; i++) {
		x10 += (x32 & ~x76) + (x54 & x76) + xkey[4*i+0];
		x10 = (x10 << 1) + (x10 >> 31 & 1);
		
		x32 += (x54 & ~x10) + (x76 & x10) + xkey[4*i+1];
		x32 = (x32 << 2) + (x32 >> 30 & 3);
		
		x54 += (x76 & ~x32) + (x10 & x32) + xkey[4*i+2];
		x54 = (x54 << 3) + (x54 >> 29 & 7);

		x76 += (x10 & ~x54) + (x32 & x54) + xkey[4*i+3];
		x76 = (x76 << 5) + (x76 >> 27 & 31);

		if (i == 4 || i == 10 || i == 16 || i == 22 || i == 28 || i == 34 || i == 40 || i == 46 || i == 52 || i == 58 ) 
		{
			x10 += xkey[x76 & 255];
			x32 += xkey[x10 & 255];
			x54 += xkey[x32 & 255];
			x76 += xkey[x54 & 255];
		}
	
		
	}

	cipher[3] = x76;
	cipher[2] = x54;
	cipher[1] = x32;
	cipher[0] = x10;

	}

/**********************************************************************\
* Decrypt an 16-byte block of ciphertext using the given key.           *
\**********************************************************************/

void rc2_decrypt(uint32_t cipher[4], uint32_t plain[4], uint32_t xkey[256])
	{
	uint32_t x76, x54, x32, x10;
	int i;

	x76 = cipher[3];
	x54 = cipher[2];
	x32 = cipher[1];
	x10 = cipher[0];

	i = 63;
	do {
	        x76 &= 0xffffffff;
		x76 = (x76 << 27) + (x76 >> 5);
		x76 -= (x10 & ~x54) + (x32 & x54) + xkey[4*i+3];

		x54 &= 0xffffffff;
		x54 = (x54 << 29) + (x54 >> 3);
		x54 -= (x76 & ~x32) + (x10 & x32) + xkey[4*i+2];
		
		x32 &= 0xffffffff;
		x32 = (x32 << 30) + (x32 >> 2);
		x32 -= (x54 & ~x10) + (x76 & x10) + xkey[4*i+1];

		x10 &= 0xffffffff;
		x10 = (x10 << 31) + (x10 >> 1);
		x10 -= (x32 & ~x76) + (x54 & x76) + xkey[4*i+0];

		if (i == 5 || i == 11 || i == 17 || i == 23 || i == 29 || i == 35 || i == 41 || i == 47 || i == 53 || i == 59 )
		{
			x76 -= xkey[x54 & 255];
			x54 -= xkey[x32 & 255];
			x32 -= xkey[x10 & 255];
			x10 -= xkey[x76 & 255];
		}
		
	} while (i--);

	plain[3] = x76;
	plain[2] = x54;
	plain[1] = x32;
	plain[0] = x10;
	
	}



void main()
{
	uint32_t xkey[256];
	uint32_t plain[4];
	uint32_t cipher[4];
	uint32_t decrypted[4];
	
	unsigned char text[33]; /* up to 256 chars for the password */
				/* password can be hexadecimal */

	unsigned char h4[n1];
	

  printf("RC2+ by Alexander PUKALL 2005 \n 128-bit block 8192-bit subkeys 64 rounds\n");
  printf("Code can be freely use even for commercial software\n");
  printf("Based on RC2 by Ronald Rivest\n\n");

    /* The key creation procedure is slow, it only needs to be done once */
    /* as long as the user does not change the key. You can encrypt and decrypt */
    /* as many blocks as you want without having to hash the key again. */
    /* init(); hashing(text,length);  end(h4); -> only once */
    /* rc2plus_init(h4,xkey); -> only once too */
    

    /* EXAMPLE 1 */
    
    init();

    strcpy((char *) text,"My secret password!0123456789abc");

    hashing(text, 32);
    end(h4); /* h4 = 8192-bit key from hash "My secret password!0123456789abc */

    rc2plus_init(h4,xkey); /* create 256 * 32-bit subkeys from h4 hash */

  
    plain[0] = 0xFEFEFEFE;
    plain[1] = 0xFEFEFEFE; /* 0xFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE RC2+ block plaintext */
    plain[2] = 0xFEFEFEFE;
    plain[3] = 0xFEFEFEFE;
    
    printf("Key 1:%s\n",text);
    printf ("Plaintext  1: %0.8lX%0.8lX%0.8lX%0.8lX\n", plain[0], plain[1], plain[2], plain[3]);
    
    rc2_encrypt(plain,cipher,xkey);

    printf ("Encryption 1: %0.8lX%0.8lX%0.8lX%0.8lX\n", cipher[0],cipher[1],cipher[2],cipher[3]);
       
    rc2_decrypt(cipher, decrypted, xkey);
    
    printf ("Decryption 1: %0.8lX%0.8lX%0.8lX%0.8lX\n\n", decrypted[0], decrypted[1], decrypted[2],decrypted[3]);


    /* EXAMPLE 2 */
    
    init();

    strcpy((char *) text,"My secret password!0123456789ABC");

    hashing(text, 32);
    end(h4); /* h4 = 8192-bit key from hash "My secret password!0123456789ABC */
   
    rc2plus_init(h4,xkey); /* create 256 * 32-bit subkeys from h4 hash */
  
    plain[0] = 0x00000000; /* 0x00000000000000000000000000000000 RC2+ block plaintext */
    plain[1] = 0x00000000; 
    plain[2] = 0x00000000;
    plain[3] = 0x00000000;
     
    printf("Key 2:%s\n",text);
    printf ("Plaintext  2: %0.8lX%0.8lX%0.8lX%0.8lX\n", plain[0], plain[1], plain[2], plain[3]);
    
    rc2_encrypt(plain,cipher,xkey);

    printf ("Encryption 2: %0.8lX%0.8lX%0.8lX%0.8lX\n", cipher[0],cipher[1],cipher[2],cipher[3]);
       
    rc2_decrypt(cipher, decrypted, xkey);
    
    printf ("Decryption 2: %0.8lX%0.8lX%0.8lX%0.8lX\n\n", decrypted[0], decrypted[1], decrypted[2],decrypted[3]);

			   
    /* EXAMPLE 3 */
    
    init();

    strcpy((char *) text,"My secret password!0123456789abZ");

    hashing(text, 32);
    end(h4); /* h4 = 8192-bit key from hash "My secret password!0123456789abZ */
   
    rc2plus_init(h4,xkey); /* create 256 * 32-bit subkeys from h4 hash */
  
    plain[0] = 0x00000000; /* 0x00000000000000000000000000000001 RC2+ block plaintext */
    plain[1] = 0x00000000; 
    plain[2] = 0x00000000;
    plain[3] = 0x00000001;
    
    printf("Key 3:%s\n",text);
    printf ("Plaintext  3: %0.8lX%0.8lX%0.8lX%0.8lX\n", plain[0], plain[1], plain[2], plain[3]);
    
    rc2_encrypt(plain,cipher,xkey);

    printf ("Encryption 3: %0.8lX%0.8lX%0.8lX%0.8lX\n", cipher[0],cipher[1],cipher[2],cipher[3]);
       
    rc2_decrypt(cipher, decrypted, xkey);
    
    printf ("Decryption 3: %0.8lX%0.8lX%0.8lX%0.8lX\n\n", decrypted[0], decrypted[1], decrypted[2],decrypted[3]);

	
}

/*
 
RC2+ by Alexander PUKALL 2005 
 128-bit block 8192-bit subkeys 64 rounds
Code can be freely use even for commercial software
Based on RC2 by Ronald Rivest

Key 1:My secret password!0123456789abc
Plaintext  1: FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE
Encryption 1: 1F39462CBE256C793D08628C73CD5927
Decryption 1: FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE

Key 2:My secret password!0123456789ABC
Plaintext  2: 00000000000000000000000000000000
Encryption 2: 88CDF31BFF81139D289DE9B4D1E51301
Decryption 2: 00000000000000000000000000000000

Key 3:My secret password!0123456789abZ
Plaintext  3: 00000000000000000000000000000001
Encryption 3: A273062103172F523151BEAFB12068A9
Decryption 3: 00000000000000000000000000000001


*/
