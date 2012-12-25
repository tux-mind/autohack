#include "parser.h"

/* check if (arg) is a vlid output file */
void parser_outfile(char *arg)
{
	struct stat out_stat;
	struct statvfs disk_stat;
	char *path=NULL;
	FILE *fout;

	if(arg == NULL)
		fatal("called with NULL argument.");
	else if(stat(arg,&out_stat) == 0)
	{
		if(S_ISREG(out_stat.st_mode))
		{
			if((path = get_full_path(arg)) != NULL)
			{
				if(access(path,W_OK) == 0)
				{
					if(statvfs(path,&disk_stat) == 0)
					{
						if((disk_stat.f_bsize * disk_stat.f_bavail) > MIN_FREE_SPACE )
						{
							argcpy(&(globals.outfile),path,strlen(path)+1);
						}
						else
							fatal_long("we need at least %lu free bytes for writing some output.",MIN_FREE_SPACE);
					}
					else
						pfatal(path);
				}
				else
					pfatal(path);
			}
			else
				fatal("unable to find full path for outfile.");
		}
		else
			fatal_long("file \"%s\" isn't a regular file.",arg);
	}
	else if(errno == ENOENT)
	{
		if((fout = fopen(arg,"w+")) != NULL)
		{
			fclose(fout);
			parser_outfile(arg); // restart
		}
		else
			pfatal(arg);
	}
	else
		pfatal(arg);

	if(path!=NULL)
		free((void *) path);

	return;
}

/* check if (arg) is a valid wordlist file */
void parser_wordlist(char *arg)
{
	struct stat wrd_stat;
#ifdef HAVE_LIBMAGIC
	const char *target_mime = "text/plain;";
#endif

	if(arg == NULL)
		fatal("called with NULL argument.");
	else if(globals.options.dict == false)
		fatal("dictionary features OFF. unable to parse wordlist.");
	else if( stat(arg,&wrd_stat) ) // if can't get file stats
		pfatal(arg);
	else if( S_ISREG(wrd_stat.st_mode) == 0 ) // if isn't a regular file
		fatal_long("\"%s\" is not a regular file.",arg);
	else if( access(arg,R_OK))
		pfatal(arg);
	else
	{
#ifdef HAVE_LIBMAGIC
		if(strncmp(get_mime(arg),target_mime,strlen(target_mime)+1) != 0)
			report(warning,"\"%s\" is not a \"%s\" file.",arg,target_mime);
#endif
		if((globals.wordlist = (const char *) get_full_path(arg)) == NULL)
			fatal("unable to resolve full path for wordlist.");
	}
	return;
}

