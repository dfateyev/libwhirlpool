/*
 * Authors:
 *   Paulo S. L. M. Barreto <pbarreto@scopus.com.br>
 *   Vincent Rijmen <vincent.rijmen@cryptomathic.com>
 *
 * This software is in the Public Domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _WHIRLPOOL_H
#define _WHIRLPOOL_H	1

#include <limits.h>

__BEGIN_DECLS

/* Definition of minimum-width integer types
 * 
 * u8   -> unsigned integer type, at least 8 bits, equivalent to unsigned char
 * u16  -> unsigned integer type, at least 16 bits
 * u32  -> unsigned integer type, at least 32 bits
 *
 * s8, s16, s32  -> signed counterparts of u8, u16, u32
 *
 * Always use macro's T8(), T16() or T32() to obtain exact-width results,
 * i.e., to specify the size of the result of each expression.
 */

typedef unsigned char	u8;

#if UINT_MAX >= 4294967295UL
typedef unsigned int	u32;
#else
typedef unsigned long	u32;
#endif

#ifdef _MSC_VER
typedef unsigned __int64	u64;
#define LL(v)   (v##i64)
#else  /* !_MSC_VER */
typedef unsigned long long	u64;
#define LL(v)   (v##ULL)
#endif /* ?_MSC_VER */

/*
 * Whirlpool-specific definitions.
 */

#define DIGESTBYTES	64
#define DIGESTBITS  (8*DIGESTBYTES)	/* 512 */

#define WBLOCKBYTES	64
#define WBLOCKBITS  (8*WBLOCKBYTES)	/* 512 */

#define LENGTHBYTES	32
#define LENGTHBITS  (8*LENGTHBYTES)	/* 256 */

typedef struct NESSIEstruct {
	u8  bitLength[LENGTHBYTES];	/* global number of hashed bits (256-bit counter) */
	u8  buffer[WBLOCKBYTES];	/* buffer of data to hash */
	int bufferBits;			/* current number of bits on the buffer */
	int bufferPos;			/* current (possibly incomplete) byte slot on the buffer */
	u64 hash[DIGESTBYTES/8];	/* the hashing state */
} NESSIEstruct;

// Core functionality
extern void whirlpool_init( struct NESSIEstruct * );
extern void whirlpool_add( unsigned char *, unsigned long, struct NESSIEstruct * );
extern void whirlpool_finalize( struct NESSIEstruct *, unsigned char * );

// Test routines
extern void whirlpool_testAPI( void );

__END_DECLS

#endif /* whirlpool.h */
