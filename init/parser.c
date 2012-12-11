#include "parser.h"

void parser_outfile(char *arg)
{
	struct stat arg_stat;
	char *path;
	FILE *f;
	
	if(arg == NULL)
		fatal("called with NULL argument.");
	else if(stat(arg,&arg_stat))
		pfatal(arg);
	else if(!S_ISREG(arg_stat.st_mode))
		fatal_long("\"%s\" is not a regular file.",arg);
	else if((path = get_full_path(arg)) == NULL ||
							access(path,W_OK) ||
							(f = fopen(path,"w")) == NULL)
		pfatal(arg);
	else
		argcpy(&globals.outfile,arg,NAME_MAX);
}