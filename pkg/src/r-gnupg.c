/*
  r-gnupg: the wrapper functions

  Copyright (C) 2011  Mario Frasca <mariotomo@inventati.org>

  $Id$

  This file is part of the gnupg packages for GNU R.
  It is made available under the terms of the GNU General Public
  License, version 2, or at your option, any later version,
  incorporated herein by reference.

  This program is distributed in the hope that it will be
  useful, but WITHOUT ANY WARRANTY; without even the implied
  warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
  PURPOSE.  See the GNU General Public License for more
  details.

  You should have received a copy of the GNU General Public
  License along with this program; if not, write to the Free
  Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
  MA 02111-1307, USA
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <R.h>
#include <Rdefines.h>
#include <Rinternals.h>
#include <gcrypt.h>


SEXP encrypt(SEXP theKey, SEXP theText) {

  char * txt;
  size_t nChar;

  if (IS_RAW(theText)) { /* Txt is either RAW */
    txt = (char*) RAW(theText);
    nChar = LENGTH(theText);
  } else { /* or a string */
    txt = (char*) STRING_VALUE(theText);
    nChar = strlen(txt);
  }

  char output[65];
  strcpy(output, "some silly hard coded result");

  SEXP theResult = NULL;
  PROTECT(theResult=allocVector(STRSXP, 1));
  SET_STRING_ELT(theResult, 0, mkChar(output));
  UNPROTECT(1);

  return theResult;
}
