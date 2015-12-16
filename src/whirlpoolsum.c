/* whirlpoolsum */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>

#include <whirlpool.h>

// ----------------------------------------------------------------------------
static int quiet_mode = 0;
static int status_mode = 0;
static int warn_mode = 0;
static int strict_mode = 0;
static int binary_mode = 0;
static int bsd_mode = 0;
static int check_mode = 0;
static int return_code = 0;

static int BUFSIZE = 8*1024*1024; // 8Mb

// ----------------------------------------------------------------------------
struct option long_options[] = {
	/* set a flag */
	{"quiet",   no_argument, &quiet_mode,  1},
	{"status",  no_argument, &status_mode, 1},
	{"strict",  no_argument, &strict_mode, 1},
	{"tag",     no_argument, &bsd_mode,    1},
	/* define an option */
	{"binary",  no_argument, 0, 'b'},
	{"check",   no_argument, 0, 'c'},
	{"text",    no_argument, 0, 't'},
	{"warn",    no_argument, 0, 'w'},
	{"test",    no_argument, 0, 'T'},
	{"help",    no_argument, 0, 'h'},
	{"version", no_argument, 0, 'V'},
	{0, 0, 0, 0}
};

// ----------------------------------------------------------------------------
void strcpy_safe ( char *dest, char *src, unsigned int count ) {

	if ( NULL == src ) dest[0] = '\0';
	else {
		strncpy( dest, src, count - 1 );
		dest[count - 1] = '\0';
	}
}

// ----------------------------------------------------------------------------
void print_help( int status ) {

	fprintf( stderr,
		"Usage: whirlpoolsum [OPTION]... [FILE]... \n"
		"Print or check Whirlpool (512-bit) checksums.\n"
		"With no FILE, or when FILE is -, read standard input.\n\n"

		"  -b, --binary         read in binary mode\n"
		"  -c, --check          read Whirlpool sums from the FILEs and check them\n"
		"      --tag            create a BSD-style checksum, in binary mode\n"
		"  -t, --text           read in text mode (default)\n"
		"  Note: There is no difference between binary and text mode option on GNU system.\n\n"

		"The following three options are useful only when verifying checksums:\n"
		"      --quiet          don't print OK for each successfully verified file\n"
		"      --status         don't output anything, status code shows success\n"
		"  -w, --warn           warn about improperly formatted checksum lines\n\n"

		"      --strict         with --check, exit non-zero for any invalid input\n"
		"      --test           invoke Whirlpool API test function and exit\n"
		"      --help           display this help and exit\n"
		"      --version        output version information and exit\n\n"

		"The sums are computed as described in the official WHIRLPOOL specs.\n"
		"When checking, the input should be a former output of this program.\n"
		"The default mode is to print a line with checksum, a character indicating\n"
		"input mode ('*' for binary, space for text), and name for each FILE.\n\n"

		"Report whirlpoolsum bugs to '" PACKAGE_BUGREPORT "'\n\n"
	);

	exit( status );
}

// ----------------------------------------------------------------------------
void print_brief_help( int status ) {

	fprintf ( stderr, "Try 'whirlpoolsum --help' for more information.\n" );

	exit( status );
}

// ----------------------------------------------------------------------------
void print_version( void ) {

	fprintf( stderr, "whirlpoolsum version " VERSION "\n"
		"This is free and unencumbered software released into the public domain.\n"
		"Anyone is free to copy, modify, publish, use, compile, sell, or\n"
		"distribute this software, either in source code form or as a compiled\n"
		"binary, for any purpose, commercial or non-commercial, and by any means.\n\n"

		"THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND,\n"
		"EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF\n"
		"MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.\n\n"

		"Authors: Paulo S.L.M. Barreto, Vincent Rijmen (Whirlpool algorithm),\n"
		"Ævar Arnfjörð Bjarmason (improvements), Denis Fateyev (whirlpoolsum).\n"
	);

	exit( EXIT_SUCCESS );
}

// ----------------------------------------------------------------------------
void print_test( void ) {

	printf( "whirlpoolsum version " VERSION "\n" );
	whirlpool_testAPI();

	exit( EXIT_SUCCESS );
}

// ----------------------------------------------------------------------------
int calculate_file_digest( char *fname, u8 *digest ) {

	FILE *infile;
	struct NESSIEstruct w;

	if ( !strcmp( fname, "-") ) { infile = stdin; }
	else { infile = (binary_mode) ? fopen( fname, "rb" ) : fopen( fname, "rt" ); }

	if ( NULL == infile ) {
		fprintf( stderr, "whirlpoolsum: %s: %s\n", fname, strerror(errno) );
		return -1;
	}

	whirlpool_init( &w );

	int num_read;
	u8 *buf = malloc( sizeof(u8)*BUFSIZE + 1 );
	if ( NULL == buf ) {
		fprintf( stderr, "whirlpoolsum: %s: Out of memory\n", fname );
		if ( infile != stdin ) fclose( infile );
		return -1;
	}

	while ( (num_read = fread(buf, sizeof(u8), BUFSIZE, infile)) ) {
		if ( num_read ) whirlpool_add( buf, 8*sizeof(u8)*num_read, &w );
		if ( ferror(infile) ) {
			fprintf( stderr, "whirlpoolsum: %s: Error in reading from file\n", fname );
			if ( infile != stdin ) fclose( infile );
			free( buf );
			return -1;
		}
	}
	free( buf );

	whirlpool_finalize( &w, digest );

	if ( infile != stdin ) fclose( infile );

	return 1;
}

// ----------------------------------------------------------------------------
void process_input_file ( char *fname ) {

	if ( check_mode ) {  /* check digest */

		FILE *infile;
		int line_size = 8096;
		// I could use PATH_MAX but it's okay here
		int path_size = 4096;

		if ( !strcmp( fname, "-") ) { infile = stdin; }
		else { infile = fopen( fname, "rt" ); }

		if ( NULL == infile ) {
			fprintf( stderr, "whirlpoolsum: %s: %s\n", fname, strerror(errno) );
			return_code = EXIT_FAILURE;
			return;
		}

		int line_no = 0;
		int line_processed = 0;
		char *fline = (char*) malloc( line_size + 1 );
		while ( fgets(fline, line_size, infile) ) {
			line_no++;
			if ( fline[strlen(fline)-1] != '\n' ) {
				if ( warn_mode ) fprintf( stderr, "whirlpoolsum: %s: Malformed line %d\n", fname, line_no );
				if ( strict_mode ) return_code = EXIT_FAILURE;
				continue;
			}

			char *found_digest;
			char *prefix = (char*) malloc( DIGESTBYTES * 2  + 1 );
			char *check_path = (char*) malloc( path_size + 1 );

			strcpy_safe( prefix, strtok(fline, " \t"), DIGESTBYTES * 2  + 1 );
			if ( !strcmp(prefix, "WHIRLPOOL") ) {

				/* bsd tag */
				free( prefix );
				strcpy_safe( check_path, strtok(NULL, ")"), path_size + 1 );
				binary_mode = 1;
				int path_len = strlen( check_path );
				if ( check_path[0] != '(' ) {
					if ( warn_mode ) fprintf( stderr, "whirlpoolsum: %s: Invalid filename in line %d\n", fname, line_no );
					if ( strict_mode ) return_code = EXIT_FAILURE;
					free( check_path );
					continue;
				}
				if ( path_len < 2) path_len = 2;
				memmove( check_path, check_path + 1, path_len - 1 );
				check_path[path_len-1] = '\0';

				char *eq_sign = (char*) malloc( 2 );
				strcpy_safe( eq_sign, strtok(NULL, " \t"), 2 );
				if ( strcmp(eq_sign, "=") ) {
					if ( warn_mode ) fprintf( stderr, "whirlpoolsum: %s: Invalid tag format in line %d\n", fname, line_no );
					if ( strict_mode ) return_code = EXIT_FAILURE;
					free( eq_sign );
					free( check_path );
					continue;
				}
				free( eq_sign );

				found_digest = (char*) malloc( DIGESTBYTES * 2 + 1 );
				strcpy_safe( found_digest, strtok(NULL, " \t\n"), DIGESTBYTES * 2 + 1 );

				if ( strlen(found_digest) != DIGESTBYTES * 2 ) {
					if ( warn_mode ) fprintf( stderr, "whirlpoolsum: %s: Invalid digest length in line %d\n", fname, line_no );
					if ( strict_mode ) return_code = EXIT_FAILURE;
					free( found_digest );
					free( check_path );
					continue;
				}
			} else {

				/* gnu version */
				if ( strlen(prefix) != DIGESTBYTES * 2 ) {
					if ( warn_mode ) fprintf( stderr, "whirlpoolsum: %s: Invalid digest length in line %d\n", fname, line_no );
					if ( strict_mode ) return_code = EXIT_FAILURE;
					free( prefix );
					free( check_path );
					continue;
				}
				found_digest = prefix;

				strcpy_safe( check_path, strtok(NULL, "\t\n"), path_size + 1 );
				int path_len = strlen( check_path );
				if ( (check_path[0] != '*') && (check_path[0] != ' ') ) {
					if ( warn_mode ) fprintf( stderr, "whirlpoolsum: %s: Invalid filename in line %d\n", fname, line_no );
					if ( strict_mode ) return_code = EXIT_FAILURE;
					free( found_digest );
					free( check_path );
					continue;
				}
				if ( check_path[0] == '*' ) binary_mode = 1;
				else binary_mode = 0;
				if ( path_len < 2) path_len = 2;
				memmove( check_path, check_path + 1, path_len - 1 );
				check_path[path_len-1] = '\0';
			}

			/* common routine */
			u8 *calc_digest = (u8*) malloc( DIGESTBYTES + 1 );
			if ( !calculate_file_digest( check_path, calc_digest ) ) {
				return_code = EXIT_FAILURE;
				free( calc_digest );
				free( found_digest );
				free( check_path );
				continue;
			}

			int i;
			char *digest_buf = (char*) malloc( DIGESTBYTES * 2 + 1 );
			char *digest_ptr = digest_buf;
			for ( i = 0; i < DIGESTBYTES; i++ ) {
				digest_ptr +=  sprintf( digest_ptr, "%02x", calc_digest[i]);
			}
			*(digest_ptr + 1) = '\0';
			free( calc_digest );

			if ( !strcasecmp(digest_buf, found_digest) ) {
				if ( !quiet_mode && !status_mode )
					fprintf( stdout, "%s: OK\n", check_path );
			} else {
				if ( !status_mode )
					fprintf( stdout, "%s: FAILED\n", check_path );
				return_code = EXIT_FAILURE;
			}

			free( digest_buf );
			free( check_path );
			free( found_digest );
			line_processed++;
		}
		free( fline );

		if ( !line_processed ) return_code = EXIT_FAILURE;

	} else {  /* calculate digest */

		u8 *digest = (u8*) malloc( DIGESTBYTES + 1 );

		/* always assume binary with bsd tags */
		if ( bsd_mode ) binary_mode = 1;

		if ( !calculate_file_digest( fname, digest ) ) {
			return_code = EXIT_FAILURE;
			free( digest );
			return;
		}

		if ( bsd_mode ) fprintf( stdout, "WHIRLPOOL (%s) = ", fname );
		int i;
		for (i = 0; i < DIGESTBYTES; i++) {
			fprintf( stdout, "%02x", digest[i]);
		}
		free( digest );
		if ( !bsd_mode ) { fprintf( stdout, " %s%s\n", ((binary_mode) ? "*" : " "), fname ); }
		else { fprintf( stdout, "\n" ); }
	}
}

// ----------------------------------------------------------------------------
int main(int argc, char **argv) {

	/* parse command line parameters */
	int c, opt_index = 0;

	while ( (c = getopt_long(argc, argv, "bctw", long_options, &opt_index) )  != -1) {

		switch (c) {
			case 'h':
				print_help( EXIT_SUCCESS );

			case 'V':
				print_version();

			case 'T':
				print_test();

			case 'b':
				binary_mode = 1;
				break;

			case 'c':
				check_mode = 1;
				break;

			case 't':
				binary_mode = 0;
				break;

			case 'w':
				warn_mode = 1;
				break;

			case 0: /* long_options flags */
				break;

			default:
				print_brief_help( EXIT_FAILURE );
		}
	}

	/* common check */
	if ( bsd_mode && check_mode ) {
		fprintf ( stderr, "the --tag option is meaningless when verifying checksums\n" );
		print_brief_help( EXIT_FAILURE );
	}

	if ( status_mode && !check_mode ) {
		fprintf( stderr, "the --status option is meaningful only when verifying checksums\n" );
		print_brief_help( EXIT_FAILURE );
	}

	if ( warn_mode && !check_mode ) {
		fprintf ( stderr, "the --warn option is meaningful only when verifying checksums\n" );
		print_brief_help( EXIT_FAILURE );
	}

	if ( quiet_mode && !check_mode ) {
		fprintf( stderr, "the --quiet option is meaningful only when verifying checksums\n" );
		print_brief_help( EXIT_FAILURE );
	}

	if ( strict_mode && !check_mode ) {
		fprintf( stderr, "the --strict option is meaningful only when verifying checksums\n" );
		print_brief_help( EXIT_FAILURE );
	}

	if ( optind == argc ) {
		/* dealing with stdin */
		process_input_file("-");
	} else {
		while (argv[optind]) {
			process_input_file( argv[optind] );
			optind++;
		}
	}

	return return_code;
}
