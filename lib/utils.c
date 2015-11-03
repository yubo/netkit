#include "utils.h"
char *
trim(char * s) {

	char * p = s;
	int l = strlen(p);

	while(isspace(p[l-1]) && l) p[--l] = 0;
	while(*p && isspace(*p) && l) ++p, --l;

	return p;
}

