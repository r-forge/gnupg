/*
 * r-gnupg.h
 *
 *  Created on: May 2, 2011
 *      Author: mario
 */

#ifndef RGNUPG_H_
#define RGNUPG_H_

/*
 ** Translation Table as described in RFC1113
 */
static const char cb64[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 ** Translation Table to decode (created by Bob Trower)
 */
static const char
		cd64[] =
				"|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

void strdecode(const unsigned char * in, unsigned char ** out);
void strencode(const unsigned char * in, unsigned char ** out);

unsigned char *signSomeText(const char * key_file_name, unsigned char * string_to_sign);

unsigned char * strFromSEXP(SEXP);

#endif /* RGNUPG_H_ */
