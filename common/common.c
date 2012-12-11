/*
 *	Autohack - automatically hack everything
 *	Copyright (C) 2012  Massimo Dragano <massimo.dragano@gmail.com>,
 *	Andrea Columpsi <andrea.columpsi@gmail.com>
 *
 *	Autohack is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *
 *	Autohack is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with Autohack.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "common.h"

/* this is the main print funtion.
 * print (call_level) followed by (msg).
 * if (use_perror) is not 0 will use perror for printing error.
 * if (fatal) is not 0 and the caller thread is the main thread will exit.
 * if global log_level is debug print (file), line number (line_no), and (caller) function before the (call_level).
 * if (msg) is NULL set the main thread id to the current one.
 */
void w_report_error(const char *msg, const char *file, int line_no, const char *caller, int use_perror, int fatal, enum _log_level call_level)
{
	char format[MAX_BUFF];
	FILE *stream;
	static pthread_t main_thread;
	struct winsize term;
	bool under_main = false;
	static const char *log_level_str[] =
	{
		"quiet",
		"error",
		"warning",
		"info",
		"verbose",
		"verbose2",
		"verbose3",
		"debug",
	};
	// this is the max excpected strings name
	static int 	max_level_len = 8,
							max_file_len = 14,
							max_line_len = 4,
							max_func_len = 20;

	if(	msg == NULL) // set main thread number.
	{
		main_thread = pthread_self();
		return;
	}
	else if(call_level > globals.log_level)
		return;
	else if(pthread_equal(pthread_self(),main_thread))
		under_main = true;

	stream = stderr;
	file = basename((char *)file);
	if(use_perror)
	{
		if(globals.log_level == debug)
			snprintf(	format,MAX_BUFF,
								"[%*s:%*d - %-*s] %-*s: \"%s\"",
								max_file_len,file,max_line_len,line_no,max_level_len,log_level_str[call_level],max_func_len,caller,msg);
		else
			snprintf( format,MAX_BUFF,
								"[%-*s]\t\"%s\"",max_level_len,log_level_str[call_level],msg);
		perror(format);
	}
	else
	{
		if(globals.log_level == debug)
			snprintf(	format,MAX_BUFF,
								"[%*s:%*d - %-*s] %-*s: %s",
								max_file_len,file,max_line_len,line_no,max_level_len,log_level_str[call_level],max_func_len,caller,msg);
		else
			snprintf( format,MAX_BUFF,
								"[%-*s]\t%s",max_level_len,log_level_str[call_level],msg);
		if(call_level >= info)
			stream = stdout;
		if(under_main==false)
		{
			ioctl(STDOUT_FILENO, TIOCGWINSZ,&term);
			fprintf(stream,"%-*c\r",term.ws_col,' '); // clean stdout
		}
		fprintf(stream,"%s\n",format);
	}
	fflush(stream);

	if(fatal)
	{
		if(under_main==true)
			destroy_all(); // only if is the main thread
		pthread_exit((void *) EXIT_FAILURE); // TODO: restart everything...we are a deamon
	}
	return;
}

int mysend(int sock, const char *buffer, long buffsize)
{
  fd_set fset;
  struct timeval tv;
  int sockStatus,
      bytesSent;
  char  *pos,
        *end;
  unsigned long blockMode;

  /* set socket to non-blocking */

  blockMode = 1;
  ioctl(sock, FIONBIO, &blockMode);

  pos = (char *) buffer;
  end = (char *) buffer + buffsize;

  while (pos < end)
  {
    bytesSent = send(sock, pos, end - pos, 0);
    if ( bytesSent < 0 )
		{
      if (bytesSent == EAGAIN)
        bytesSent = 0;
      else
			{
						w_report_error("send()",__FILE__,__LINE__,__func__,1,0,warning);
        return 0;
			}
		}
    pos += bytesSent;
    if ( pos >= end )
      break;
    FD_ZERO(&fset);
    FD_SET(sock, &fset);
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    sockStatus = select(sock + 1, NULL, &fset, &fset, &tv);
    if (sockStatus <= 0)
      return 0;

  }
  return 1;
}

/* wrapper for socket */
int w_socket(int domain, int type, int protocol, const char *file, int line_no)
{
        int socket_return;
        socket_return = socket(domain, type, protocol);
        if(socket_return == -1)
							w_report_error("socket()", file, line_no,__func__, 1,1,error);
        return socket_return;
}

/* wrapper for bind */
int w_bind(int sockfd, struct sockaddr *addr, socklen_t len, const char *file, int line_no)
{
        int bind_return;
        bind_return = bind(sockfd, addr, len);

        if ( bind_return == -1 )
					w_report_error("bind()", file, line_no,__func__, 1, 1, error);
				return bind_return;
}

/* wrapper for listen */
int w_listen(int sockfd, int backlog, const char *file, int line_no)
{
        int listen_return;
        listen_return = listen(sockfd, backlog);
        if(listen_return == -1)
					w_report_error("listen()", file, line_no,__func__, 1, 0, error);
				return listen_return;
}

/* wrapper for malloc
 * it initialize allocated data with '\0'
 */
void *w_malloc(size_t bytes, const char *file, int line_no)
{
	void *memory = NULL;
	memory = malloc(bytes);
	if (!memory)
		w_report_error("malloc()", file, line_no,__func__, 1, 1, error);
	memset(memory,'\0',bytes);
	return memory;
}

/* wrapper for tmpnam */
void w_tmpnam(char *tmpfile,const char *file, int line_no, const char *caller)
{
	if(tmpnam(tmpfile) == NULL)
		w_report_error("cannot create temporary files.",file,line_no,caller,0,1,error);
	return;
}

/* execute regex (patrn) on (string)
 * return the (nmatch)th result
 * e.g. string="test0the0function", patrn="([a-z]+)"
 *      nmatch => 1:"test0the0function", 2:"test", 3:"the", 4:"function"
 */
char *w_regexp(const char *string, const char *patrn, size_t nmatch, const char *file, int line_no, const char *caller)
{
	int i, w=0, len,begin,end;
	char *word = NULL;
	regex_t rgT;
	regmatch_t *pmatch;

	if( string == NULL || patrn == NULL)
		w_report_error("called with NULL pointer.",file,line_no,__func__,0,1,error);
	else if(strlen(string) == 0)
		return NULL;
	else if(nmatch <= 0 || nmatch > 20)
	{
		w_report_error("called with invalid index.",file,line_no,__func__,0,0,error);
		return NULL;
	}

	if (regcomp(&rgT,patrn,REG_EXTENDED | REG_NEWLINE) != 0)
	{
		pthread_mutex_lock(&(globals.err_buff_lock));
		snprintf(globals.err_buff,MAX_BUFF,"bad regex: \"%s\"",patrn);
		w_report_error(globals.err_buff,file,line_no,__func__,0,0,error);
		pthread_mutex_unlock(&(globals.err_buff_lock));
		return NULL;
	}

	pmatch = malloc(nmatch*sizeof(regmatch_t));

	if ((regexec(&rgT,string,nmatch,pmatch,0)) == 0)
	{
		begin = (int)pmatch[nmatch-1].rm_so;
		end = (int)pmatch[nmatch-1].rm_eo;
		len = (int) end - begin;
		if(len!=0)
		{
			word=malloc(len+1);
			for (i=begin; i<end; i++)
			{
				word[w] = string[i];
				w++;
			}
			word[w]='\0';
		}
	}
	free(pmatch);
	regfree(&rgT);
	return word;
}

/* get the number of processors on this machine */
int get_n_cpus()
{
	#ifdef __WIN__
	SYSTEM_INFO sysinfo;
	GetSystemInfo( &sysinfo );
	return sysinfo.dwNumberOfProcessors;
	#elif defined(_SC_NPROCESSORS_ONLN)
	return sysconf( _SC_NPROCESSORS_ONLN);
	#elif defined(__BSD__) || defined(MACOS)
	int mib[4],num;
	size_t len = sizeof(num);

	mib[0] = CTL_HW;
	mib[1] = HW_AVAILCPU;
	sysctl(mib, 2, &num, &len, NULL, 0);
	if(num < 1)
	{
		mib[1] = HW_NCPU;
		sysctl(mib, 2, &num, &len, NULL, 0);
		if(num<1)
			num = 1;
	}
	return num;
	#elif defined(__HPUX__)
	return mpctl(MPC_GETNUMSPUS, NULL, NULL);
	#elif defined(__IRIX__)
	return sysconf(_SC_NPROC_ONLN);
	#else
		#error cannot detect machine arch.
	#endif
}

/* compute the hash for (pswd) using the (type) method */
char *w_digest(unsigned char *pswd, /*char *salt,*/hash_type type, const char *file, int line_no)
{

	switch(type)
	{
		case md5:
			return md5_crypt(pswd);
			break;
		case MYSQL3:
			return mysql3_crypt(pswd);
			break;
		case MYSQL:
			return mysql_crypt(pswd);
			break;
		case NT:
			return ntlm_crypt((char *) pswd);
			break;
		case sha1:
			return sha1_crypt(pswd);
			break;
		case sha256:
			return sha256_crypt(pswd);
			break;
		case sha384:
			return sha384_crypt(pswd);
			break;
		case sha512:
			return sha512_crypt(pswd);
			break;
		default:
			pthread_mutex_lock(&(globals.err_buff_lock));
			snprintf(globals.err_buff,MAX_BUFF,"reverse check for this type \"%s\" is not yet supported.", hash_type_str[type]);
			w_report_error(globals.err_buff,file,line_no,__func__,0,0,warning);
			snprintf(globals.err_buff,MAX_BUFF,"given value: %d .",type);
			w_report_error(globals.err_buff,file,line_no,__func__,0,0,debug);
			pthread_mutex_unlock(&(globals.err_buff_lock));
	}
	/* no digest produce less then 6 chars, so the check will surely fail.*/
	return "FAIL";
}

/* return a new string that is the lowercase copy of the (arg) */
char *w_str2low(const char *arg,const char *file,int line_no)
{
	size_t len;
	char *str,*ptr;

	len = strlen(arg);
	str = w_malloc((len+1)*sizeof(char),file,line_no);
	strncpy(str,arg,len);
	str[len] = '\0';
	for(ptr=str;*ptr!='\n'&&*ptr!='\0';ptr++)
		*ptr = (char) tolower(*ptr);
	*ptr = '\0';
	return str;
}

/* return a new string that is the uppercase copy of the (arg) */
char *w_str2up(const char *arg,const char *file,int line_no)
{
	size_t len;
	char *str,*ptr;

	len = strlen(arg);
	str = w_malloc((len+1)*sizeof(char),file,line_no);
	strncpy(str,arg,len);
	str[len] = '\0';
	for(ptr=str;*ptr!='\n'&&*ptr!='\0';ptr++)
		*ptr = (char) toupper(*ptr);
	*ptr = '\0';
	return str;
}

/* TODO */
void w_write_out(_hash *hash, _wpa *wpa, const char *file, int line_no, const char *caller)
{
	FILE *fd=NULL;
	char buffer[MAX_LINE],*value;
	size_t len;
	bool yet_found;

	if(globals.outfile==NULL)
		return;

	fd = fopen(globals.outfile,"a+"); // all checks are yet done by parser_outfile
	yet_found = false;
	fgets(buffer,MAX_LINE,fd);
	while(!feof(fd) && yet_found == false)
	{
		len = strlen(buffer);
		if(buffer[len-1] == '\n')
		{
			value = w_regexp(buffer,"\\$([^$]+)\\$([^:]+):.*",2,__FILE__,__LINE__,__func__);
			if(value != NULL)
			{
				if(strncmp(value,"WPA",4))
				{
					if(hash!=NULL)
					{
						free((void *) value);
						value = w_regexp(buffer,"\\$([^$]+)\\$([^:]+):.*",3,__FILE__,__LINE__,__func__);
						len = strlen(value)+1;
						if(!strncmp(value,hash->hash,len))
							yet_found = true;
					}
				}
				else
				{
					if(wpa!=NULL)
					{
						free((void *) value);
						value = w_regexp(buffer,"\\$([^$]+)\\$([^:]+):.*",3,__FILE__,__LINE__,__func__);
						len = strlen(value)+1;
						if(!strncmp(value,wpa->essid,len))
							yet_found = true;
					}
				}
				free((void *) value);
			}
		}
		fgets(buffer,MAX_LINE,fd);
	}

	if(yet_found==true)
		return;
	else if(hash != NULL)
		fprintf(fd,"$%s$%s:%s\n",hash_type_str[hash->type],hash->hash,hash->plain);
	else if(wpa != NULL)
		fprintf(fd,"$WPA$%s:%s\n",wpa->essid,wpa->key);
	else
	{
		fclose(fd);
		w_report_error("called with NULL argument.",file,line_no,__func__,0,1,error);
	}

	fclose(fd);
	return;
}

/* add the hash (hash_arg) of type (type) to the global hash_list. */
void w_add_hash( hash_type type,const char *hash_arg, const char *file, int line_no)
{
	char *hash=NULL;
	static unsigned int id = 0;
	_hash *tmp;


	if( hash_arg != NULL )
		hash = w_str2low(hash_arg,file,line_no);

	if( hash != NULL && type != NONE )
	{
		if(globals.hash_list!=NULL)
		{
			for(tmp=globals.hash_list;tmp->next!=NULL;tmp=tmp->next);
			tmp = tmp->next = (_hash *) w_malloc(sizeof(_hash),file, line_no);
		}
		else
		{
			tmp = globals.hash_list = (_hash *) w_malloc(sizeof(_hash),file, line_no);
		}
		tmp->next = NULL;
		tmp->type = type;
		tmp->hash = hash;
		tmp->plain = NULL;
		tmp->id = id;
		id++;
	}
	else
	{
		w_report_error("unexcepted call.",file,line_no,__func__,0,0,error);
		if(globals.log_level == debug)
		{
		 	pthread_mutex_lock(&globals.err_buff_lock);
			if(type < N_TYPE && type >= 0)
			{
				snprintf(	globals.err_buff, MAX_BUFF, "\ttype:\t\"%s\"", hash_type_str[type] );
				w_report_error(globals.err_buff,file,line_no,__func__,0,0,debug);
			}
			else
				w_report_error("unexpected hash type.",file,line_no,__func__,0,0,debug);
			if( hash_arg != NULL )
			{
				snprintf(	globals.err_buff,MAX_BUFF,"\thash:\t\"%s\"",hash_arg);
				w_report_error(globals.err_buff,file,line_no,__func__,0,0,debug);
			}
			else
				w_report_error("\thash:\tNULL",file,line_no,__func__,0,0,debug);
			pthread_mutex_unlock(&globals.err_buff_lock);
		}
		w_report_error("quitting...",file,line_no,__func__,0,1,error);
	}
}

/* add interface with (name) to the global iface_list. */
void w_add_iface( char *name, char *file, int line_no, const char *func)
{
	static unsigned int id = 0;
	_iface *itmp;

	if(name == NULL)
		w_report_error("called with NULL argument.",file,line_no,__func__,0,0,error);
	else
	{
		if(globals.iface_list == NULL)
			itmp = globals.iface_list = w_malloc(sizeof(_iface),__FILE__,__LINE__);
		else
		{
			for(itmp = globals.iface_list;itmp->next;itmp=itmp->next);
			itmp = itmp->next = w_malloc(sizeof(_iface),__FILE__,__LINE__);
		}
		itmp->next = NULL;
		itmp->id = id++;
		w_argcpy(&(itmp->name),name,MAX_BUFF,__FILE__,__LINE__,__func__);
	}
}

/* delete interface (del_item) from global iface_list. */
void w_del_iface( _iface *del_item, char *file, int line_no, const char *func)
{
	_iface *itmp = NULL,*iold = NULL;

	if(del_item == NULL)
		w_report_error("called with NULL argument.",file,line_no,__func__,0,0,error);
	else
	{
		for(itmp = globals.iface_list;itmp && itmp != del_item;itmp=itmp->next)
			iold=itmp;
		if(itmp == NULL)
		{
			pthread_mutex_lock(&(globals.err_buff_lock));
			snprintf(globals.err_buff,MAX_BUFF,"interface #%d not in iface_list.",del_item->id);
			w_report_error(globals.err_buff,file,line_no,__func__,0,0,error);
			pthread_mutex_unlock(&(globals.err_buff_lock));
		}
		else if(iold == NULL) /* delete the first item of the list */
		{
			globals.iface_list = itmp->next;
			free_iface(itmp);
		}
		else
		{
			iold->next = itmp->next;
			free_iface(itmp);
		}
	}
}

/* free a iface struct. */
void free_iface(_iface *item)
{
	if(item->name != NULL)
		free((void *) item->name);
	if(item->path != NULL)
		free((void *) item->path);
	if(item->internal_name != NULL)
		free((void *) item->internal_name);
	free(item);
}

/* delete the (del_item) hash from the global hash_list */
void w_del_hash(_hash *del_item, const char *file, int line_no)
{
	_hash *tmp;

	if(del_item == NULL)
		w_report_error("called with NULL pointer.",file,line_no,__func__,0,1,error);
	if(globals.hash_list==NULL)
		w_report_error("global hash_list is empty.",file,line_no,__func__,0,1,error);

	if(del_item != globals.hash_list)
	{
		for(tmp=globals.hash_list;tmp->next != NULL && tmp->next != del_item; tmp=tmp->next);

		if(tmp->next == NULL)
		{
			w_report_error("item to delete is not in hash_list.",file,line_no,__func__,0,0,warning);
			return;
		}
		tmp->next = del_item->next;
	}
	else
		globals.hash_list = del_item->next;

	free((void *) del_item->hash);
	free((void *) del_item);
	return;
}

/* add the (plain) text found for the (hash|found_hash) to the hash_list */
void w_add_hash_plain(_hash *found_hash, char *hash, struct t_info *thread, char *plain, const char *file, int line_no)
{
	_hash *htmp=NULL;
	size_t len;

	if(plain == NULL)
		w_report_error("called with NULL argument.",file,line_no,__func__,0,0,error);
	else if(found_hash!=NULL)
		htmp=found_hash;
	else if(found_hash==NULL && hash!=NULL)
	{
		len = strlen(hash)+1;
		for(htmp=globals.hash_list;htmp!=NULL && strncmp(hash,htmp->hash,len);htmp=htmp->next);
	}

	if(htmp==NULL)
	{
		w_report_error("cannot find hash structure for the find one.",file,line_no,__func__,0,0,error);
		return;
	}
	pthread_mutex_lock(&(htmp->lock));
	len = strlen(plain)+1;
	if(strncmp(htmp->hash,w_digest((unsigned char *) plain,htmp->type,file,line_no),len))
	{
		w_report_error("bad password found!",file,line_no,__func__,0,0,verbose);
		pthread_mutex_lock(&(globals.err_buff_lock));
		snprintf(globals.err_buff,MAX_LINE,"id  :\t%u",htmp->id);
		w_report_error(globals.err_buff,file,line_no,__func__,0,0,verbose3);
		snprintf(globals.err_buff,MAX_LINE,"type:\t%s",hash_type_str[htmp->type]);
		w_report_error(globals.err_buff,file,line_no,__func__,0,0,verbose2);
		snprintf(globals.err_buff,MAX_LINE,"hash:\t%s",htmp->hash);
		w_report_error(globals.err_buff,file,line_no,__func__,0,0,verbose);
		snprintf(globals.err_buff,MAX_LINE,"bad pswd: \"%s\"",plain);
		w_report_error(globals.err_buff,file,line_no,__func__,0,0,verbose);
		pthread_mutex_unlock(&(globals.err_buff_lock));
	}
	else
	{
		if(htmp->plain != NULL)
		{
			pthread_mutex_lock(&(globals.err_buff_lock));
			if(strncmp(htmp->plain,plain,len))
			{
				w_report_error("password already found, but with different value.",file,line_no,__func__,0,0,warning);
				snprintf(globals.err_buff,MAX_LINE,"id  :\t%u",htmp->id);
				w_report_error(globals.err_buff,file,line_no,__func__,0,0,verbose2);
				snprintf(globals.err_buff,MAX_LINE,"type:\t%s",hash_type_str[htmp->type]);
				w_report_error(globals.err_buff,file,line_no,__func__,0,0,verbose);
				snprintf(globals.err_buff,MAX_LINE,"hash:\t%s",htmp->hash);
				w_report_error(globals.err_buff,file,line_no,__func__,0,0,verbose);
				snprintf(globals.err_buff,MAX_LINE,"old pswd: \"%s\"",htmp->plain);
				w_report_error(globals.err_buff,file,line_no,__func__,0,0,info);
				snprintf(globals.err_buff,MAX_LINE,"new pswd: \"%s\"",plain);
				w_report_error(globals.err_buff,file,line_no,__func__,0,0,info);
				w_report_error("the new password text will be used.",file,line_no,__func__,0,0,verbose);
			}
			else
			{
				snprintf(globals.err_buff,MAX_LINE,"password \"%s\" found again.",plain);
				w_report_error(globals.err_buff,file,line_no,__func__,0,0,verbose2);
			}
			pthread_mutex_unlock(&(globals.err_buff_lock));
			free((void *) htmp->plain);
			htmp->plain = w_malloc(len*sizeof(char),__FILE__,__LINE__);
			strncpy(htmp->plain,plain,len);
		}
		else
		{
			w_report_error("found password!",file,line_no,__func__,0,0,info);
			pthread_mutex_lock(&(globals.err_buff_lock));
			snprintf(globals.err_buff,MAX_LINE,"id  :\t%u",htmp->id);
			w_report_error(globals.err_buff,file,line_no,__func__,0,0,verbose2);
			snprintf(globals.err_buff,MAX_LINE,"type:\t%s",hash_type_str[htmp->type]);
			w_report_error(globals.err_buff,file,line_no,__func__,0,0,verbose);
			snprintf(globals.err_buff,MAX_LINE,"hash:\t%s",htmp->hash);
			w_report_error(globals.err_buff,file,line_no,__func__,0,0,info);
			snprintf(globals.err_buff,MAX_LINE,"pswd:\t%s",plain);
			w_report_error(globals.err_buff,file,line_no,__func__,0,0,info);
			pthread_mutex_unlock(&(globals.err_buff_lock));
			htmp->plain = w_malloc(len*sizeof(char),__FILE__,__LINE__);
			strncpy(htmp->plain,plain,len);
			//w_write_out(htmp,NULL,__FILE__,__LINE__,__func__);
		}
	}
	pthread_mutex_unlock(&(htmp->lock));
	return;
}

/* TODO: split up; print the list of known hash and WPA
 * TODO: print also hosts and subnets
 */
void print_lists()
{
	_hash *tmp=NULL;
	_wpa *wpa=NULL;
	_iface *itmp=NULL;
	unsigned int id_max;
	int type_max,hash_max,plain_max,len,i;
	void *limit[4];
	char line[MAX_BUFF],format[MAX_BUFF],*ptr,*end;


	if(globals.hash_list==NULL && globals.wpa_list == NULL && globals.iface_list == NULL)
		return;
	if(globals.hash_list!=NULL)
	{
		// set minimum values for correct formatting
		id_max = 2;/*strlen("ID");*/
		type_max = 4;/*strlen("TYPE");*/
		hash_max = 4;/*strlen("HASH");*/
		plain_max = 10;/*strlen("PLAIN TEXT");*/

		limit[0] = (void *) &id_max;
		limit[1] = (void *) &type_max;
		limit[2] = (void *) &hash_max;
		limit[3] = (void *) &plain_max;

		for(tmp=globals.hash_list;tmp != NULL; tmp=tmp->next)
		{
			if( ( tmp->id / (id_max * 10)) > 0)
				id_max = snprintf(NULL,0,"%d",tmp->id);
			if( tmp->hash != NULL && ( (len=strlen(tmp->hash)) > hash_max ) )
				hash_max = len;
			if( tmp->type != NONE && ( (len=strlen(hash_type_str[tmp->type])) > type_max ) )
				type_max = len;
			if( tmp->plain != NULL && ( (len=strlen(tmp->plain)) > plain_max ) )
				plain_max = len;
		}

		// building line
		// "+-----+---------+----------------------------------------+---------------+"
		ptr=line;
		end= ptr + MAX_BUFF;
		*ptr = '+';
		ptr++;

		// use len as counter
		for(i=0;i<4;i++,*ptr='+',ptr++)
			for(len = 0; len < *((int *) limit[i]) && ptr < end;len++,ptr++)
				*ptr='-';
		*ptr='\n';
		ptr++;
		*ptr='\0';

		snprintf(format,MAX_BUFF,"|%-*s|%-*s|%-*s|%-*s|\n",id_max,"ID",type_max,"TYPE",hash_max,"HASH",plain_max,"PLAIN TEXT");
		printf("\n%s%s%s",line,format,line); // print head
		for(tmp=globals.hash_list;tmp!=NULL;tmp=tmp->next)
		{
			if(tmp->hash == NULL)
				ptr="";
			else
				ptr=tmp->hash;
			if(tmp->plain == NULL)
				end="";
			else
				end=tmp->plain;
			printf("|%-*u|%-*s|%-*s|%-*s|\n",id_max,tmp->id,type_max,hash_type_str[tmp->type],hash_max,ptr,plain_max,end);
		}
		printf("%s",line);
	}

	if(globals.wpa_list!=NULL)
	{
		id_max = 2;/*strlen("ID");*/
		hash_max = 5;/*strlen("ESSID");*/
		plain_max = 10;/*strlen("PASSPHRASE");*/

		limit[0] = (void *) &id_max;
		limit[1] = (void *) &hash_max;
		limit[2] = (void *) &plain_max;

		for(wpa=globals.wpa_list;wpa != NULL; wpa=wpa->next)
		{
			if( ( wpa->id / (id_max * 10)) > 0)
				id_max = log10(wpa->id);
			if( wpa->essid != NULL && ( (len=strlen(wpa->essid)) > hash_max ) )
				hash_max = len;
			if( wpa->key != NULL && ( (len=strlen(wpa->key)) > plain_max ) )
				plain_max = len;
		}

		// building line
		// "+-----+---------+----------------------------------------+---------------+"
		ptr=line;
		end= ptr + MAX_BUFF;
		*ptr = '+';
		ptr++;

		// use len as counter
		for(i=0;i<3;i++,*ptr='+',ptr++)
			for(len = 0; len < *((int *) limit[i]) && ptr < end;len++,ptr++)
				*ptr='-';
		*ptr='\n';
		ptr++;
		*ptr='\0';

		snprintf(format,MAX_BUFF,"|%-*s|%-*s|%-*s|\n",id_max,"ID",hash_max,"ESSID",plain_max,"PASSPHRASE");
		printf("\n%s%s%s",line,format,line);

		for(wpa=globals.wpa_list;wpa!=NULL;wpa=wpa->next)
		{
			if(wpa->essid==NULL)
				ptr="";
			else
				ptr=wpa->essid;
			if(wpa->key==NULL)
				end="";
			else
				end=wpa->key;
			printf("|%-*u|%-*s|%-*s|\n",id_max,wpa->id,hash_max,ptr,plain_max,end);
		}

		printf("%s",line);
	}

	if(globals.iface_list != NULL)
	{
		id_max = 2;/*strlen("ID");*/
		hash_max = 5;/*strlen("IFACE");*/
		plain_max = 4;/*strlen("NAME");*/

		limit[0] = (void *) &id_max;
		limit[1] = (void *) &hash_max;
		limit[2] = (void *) &plain_max;

		for(itmp = globals.iface_list;itmp;itmp=itmp->next)
		{
			if( ( itmp->id / (id_max * 10)) > 0)
				id_max = log10(itmp->id);
			if( itmp->name != NULL && (len=strlen(itmp->name)) > hash_max)
				hash_max = len;
			if( itmp->internal_name != NULL && (len = strlen(itmp->internal_name)) > plain_max)
				plain_max = len;
		}

		// building line
		// "+-----+---------+----------------------------------------+---------------+"
		ptr=line;
		end= ptr + MAX_BUFF;
		*ptr = '+';
		ptr++;

		// use len as counter
		for(i=0;i<3;i++,*ptr='+',ptr++)
			for(len = 0; len < *((int *) limit[i]) && ptr < end;len++,ptr++)
				*ptr='-';
		*ptr='\n';
		ptr++;
		*ptr='\0';

		snprintf(format,MAX_BUFF,"|%-*s|%-*s|%-*s|\n",id_max,"ID",hash_max,"IFACE",plain_max,"NAME");
		printf("\n%s%s%s",line,format,line);

		for(itmp=globals.iface_list;itmp!=NULL;itmp=itmp->next)
		{
			if(itmp->name==NULL)
				ptr="";
			else
				ptr=(char *)itmp->name;
			if(itmp->internal_name==NULL)
				end="";
			else
				end=itmp->internal_name;
			printf("|%-*u|%-*s|%-*s|\n",id_max,itmp->id,hash_max,ptr,plain_max,end);
		}

		printf("%s",line);

	}
	return;
}

/* print the list of supported hash types and exit */
void print_type_list()
{
	int i;

	printf("Supported hash:\n");
	// exclude NONE and UNKNOWN
	for (i=1;i<(N_TYPE-1);i++)
		printf("\t%s\n",hash_type_str[i]);
	destroy_all();
	exit(EXIT_SUCCESS);
	return;
}

/* find the first file that match (file) in directory (indirectory) and subdirs */
char *find_file(const char *indirectory, const char *file)
{
	struct dirent *d;
	DIR *dir;
	char 	*file_path,
				*subdirectory,
				*directory;
	int found;

	if(indirectory == NULL || file == NULL)
	{
		w_report_error("called with NULL argument.",__FILE__,__LINE__,__func__,0,0,error);
		return NULL;
	}

	file_path = w_malloc(NAME_MAX*sizeof(char),__FILE__,__LINE__);

	// use found for store the size of the input directory lenght
	found = strlen(indirectory) + 2; // // one for the optional extra '/'
	directory = w_malloc(found*sizeof(char),__FILE__,__LINE__);
	strncpy(directory,indirectory,found);
	if(directory[found - 3] != '/')
		strncat(directory,"/",1);
	strncpy(file_path,"",NAME_MAX);
	found = 0;

	if( (dir = opendir(directory)) == NULL )
		return NULL;

	// first search in the top directory
	while( ( d = readdir(dir) ) != NULL && !found)
		if(	d->d_type != DT_DIR &&
				fnmatch(file,d->d_name,FNM_PATHNAME) == 0 )
		{
			snprintf(file_path,NAME_MAX,"%s%s",directory,d->d_name);
			found = 1;
		}


	closedir(dir);
	if(found)
	{
		free(directory);
		return file_path;
	}
	free((void *) file_path);
	subdirectory = w_malloc(NAME_MAX*sizeof(char),__FILE__,__LINE__);
	dir = opendir(directory);

	// scan all subdirectory ( not "." and ".." )
	while( ( d = readdir(dir) ) != NULL && !found)
		if(	d->d_type == DT_DIR &&
				strncmp(d->d_name,".",2) &&
				strncmp(d->d_name,"..",3))
		{
			snprintf(subdirectory,NAME_MAX,"%s%s",directory,d->d_name);
			if( (file_path = find_file(subdirectory,file)) != NULL )
				found = 1;
		}

	free(subdirectory);
	free(directory);
	closedir(dir);

	if(found)
		return file_path;
	else
		return NULL;
}

/* return the full path of file (arg) */
char *w_get_full_path( const char *arg, const char *file,int line_no,const char *caller)
{
	char *fpath,*buffer;
	size_t len;
	bool found;

	fpath = buffer = NULL;
	found = false;

	if(arg==NULL)
		w_report_error("called with NULL argument.",file,line_no,__func__,0,1,error);
	else if((len=strlen(arg)) <= 0)
		w_report_error("try to resolve path for an empty string.",file,line_no,caller,0,0,warning);
	else if(len >= PATH_MAX)
	{
		w_report_error("!!! SECURITY BREACH !!!",file,line_no,caller,0,0,quiet);
		w_report_error("try to resolve path for a too large filename.",file,line_no,caller,0,1,error);
	}
	else
	{
		fpath = w_malloc((PATH_MAX+1)*sizeof(char),__FILE__,__LINE__);
		buffer = w_malloc((PATH_MAX+1)*sizeof(char),__FILE__,__LINE__);
		strncpy(buffer,arg,PATH_MAX);
		if(realpath(buffer,fpath) == NULL) // arg isn't a full path
		{
			if(getcwd(fpath,PATH_MAX) == NULL)
				w_report_error("getcwd()",file,line_no,caller,1,0,error);
			else
			{
				snprintf(buffer,PATH_MAX,"%s/%s",fpath,arg);
				pthread_mutex_lock(&(globals.err_buff_lock));
				snprintf(globals.err_buff,MAX_BUFF,"\"%s\"",buffer);
				if(realpath(buffer,fpath) == NULL)
				{
					w_report_error("while try to resolve absolute pathname:",file,line_no,caller,0,0,verbose);
					w_report_error(globals.err_buff,file,line_no,caller,1,0,error);
				}
				else
					found = true;
				pthread_mutex_unlock(&(globals.err_buff_lock));
			}
		}
		else
			found = true;
	}

	if(found == true)
	{
		len = strlen(fpath)+1;
		strncpy(buffer,fpath,PATH_MAX);
		free((void *) fpath);
		fpath = malloc(len*sizeof(char));
		strncpy(fpath,buffer,len);
	}
	else if(fpath!=NULL)
	{
		free((void *) fpath);
		fpath = NULL;
	}

	if(buffer!=NULL)
		free((void *) buffer);

	return fpath;
}

/* add the wpa handshake in (hccap) for (essid) in the global wpa list */
void w_add_wpa(char *essid, hccap_t *hccap, const char *file, int line_no)
{
	struct _wpa *iter=NULL,*prev=NULL;
	size_t elen;
	bool yet_loaded;

	if(essid == NULL)
		w_report_error("called with NULL argument.",file,line_no,__func__,0,0,error);
	else if((elen = strlen(essid)) == 0 || elen > 32)
	{
		pthread_mutex_lock(&(globals.err_buff_lock));
		snprintf(globals.err_buff,MAX_BUFF,"invalid essid \"%s\".",essid);
		w_report_error(globals.err_buff,file,line_no,__func__,0,0,warning);
		pthread_mutex_unlock(&(globals.err_buff_lock));
	}
	else
	{
		elen++; // space for '\0'
		yet_loaded = false;
		for(iter=globals.wpa_list;iter!=NULL && strncmp(iter->essid,essid,elen);prev=iter,iter=iter->next);

		if(iter != NULL)
			yet_loaded = true;
		else if(prev == NULL) // wpa_list is empty
		{
			iter = globals.wpa_list = w_malloc(sizeof(struct _wpa),file,line_no);
			iter->id = 0;
		}
		else // no AP matched
		{
			prev->next = iter = w_malloc(sizeof(struct _wpa),file,line_no);
			iter->id = prev->id +1;
		}

		if( hccap != NULL) // maybe a scan result want use wpa list for store active essid...
		{
			if(iter->hccap==NULL)
				iter->hccap = w_malloc(sizeof(hccap_t),file,line_no);
			else
			{
				pthread_mutex_lock(&(globals.err_buff_lock));
				snprintf(globals.err_buff,MAX_BUFF,"reloading capture data for essid \"%s\".",iter->essid);
				w_report_error(globals.err_buff,file,line_no,__func__,0,0,verbose2);
				pthread_mutex_unlock(&(globals.err_buff_lock));
				yet_loaded = true;
			}
			memcpy(iter->hccap,hccap,sizeof(hccap_t));
		}

		if(iter->essid==NULL)
		{
			iter->essid = w_malloc(elen*sizeof(char),__FILE__,__LINE__);
			strncpy(iter->essid,essid,elen);
		}

		if(yet_loaded == false)
		{
			pthread_mutex_lock(&(globals.err_buff_lock));
			snprintf(globals.err_buff,MAX_BUFF,"essid \"%s\" loaded.",iter->essid);
			w_report_error(globals.err_buff,file,line_no,__func__,0,0,info);
			pthread_mutex_unlock(&(globals.err_buff_lock));
		}
	}

	return;
}

/* compute the keymic from (wpa) with supplied (key), and compare with the found one.
 * lot of this code is taken from aircrack-ng suite */
bool test_wpa_key(hccap_t *wpa, char *key)
{
	int i;
	uchar pmk[128];

	uchar pke[100];
	uchar ptk[80];
	uchar mic[20];

	/* pre-compute the key expansion buffer */
	memcpy( pke, "Pairwise key expansion", 23 );
	if( memcmp( wpa->mac2, wpa->mac1, 6 ) < 0 )	{
		memcpy( pke + 23, wpa->mac2, 6 );
		memcpy( pke + 29, wpa->mac1, 6 );
	} else {
		memcpy( pke + 23, wpa->mac1, 6 );
		memcpy( pke + 29, wpa->mac2, 6 );
	}
	if( memcmp( wpa->nonce1, wpa->nonce2, 32 ) < 0 ) {
		memcpy( pke + 35, wpa->nonce1, 32 );
		memcpy( pke + 67, wpa->nonce2, 32 );
	} else {
		memcpy( pke + 35, wpa->nonce2, 32 );
		memcpy( pke + 67, wpa->nonce1, 32 );
	}

	calc_pmk( key, wpa->essid, pmk );
	for (i = 0; i < 4; i++)
	{
		pke[99] = i;
		HMAC(EVP_sha1(), pmk, 32, pke, 100, ptk + i * 20, NULL);
	}

	if(wpa->keyver == 1)
		HMAC(EVP_md5(), ptk, 16, wpa->eapol, wpa->eapol_size, mic, NULL);
	else
		HMAC(EVP_sha1(), ptk, 16, wpa->eapol, wpa->eapol_size, mic, NULL);

	if(memcmp(mic,wpa->keymic,16) == 0)
		return true;
	return false;
}

/* free a wpa struct */
void free_wpa(_wpa *delete)
{
	if(delete->essid != NULL)
		free((void *) delete->essid);
	if(delete->key != NULL)
		free((void *) delete->key);
	if(delete->hccap !=NULL)
		free((void *) delete->hccap);
	free((void *) delete);
	return;
}

/* fgets return the read (string) plus a '\n', this function remove that */
char *w_fgets_fix(char *string, const char *file, int line_no, const char *caller)
{
	char *ptr;

	if(string == NULL)
		w_report_error("called with NULL pointer.",file,line_no,caller,0,1,error);

	for(ptr=string;*ptr!='\n'&&*ptr!='\0';ptr++);
	*ptr='\0';
	return string;
}

#ifdef HAVE_LIBMAGIC
/* return the MIME time of the file (arg)
 * if called with NULL (arg), will free the static magic_full.
 */
const char *w_get_mime(const char *arg, const char *file, int line_no)
{
	const char *buff;
	static char *magic_full=NULL;
	size_t len;
	magic_t magic_cookie;

	if(arg == NULL)
		free(magic_full);
	else if ((magic_cookie = magic_open(MAGIC_MIME) ) == NULL)
		w_report_error("unable to initialize magic library.",__FILE__,__LINE__,__func__,0,1,error);
	else if (magic_load(magic_cookie, NULL) != 0)
	{
		magic_close(magic_cookie);
		snprintf(globals.err_buff,MAX_BUFF,"cannot load magic database - %s .",magic_error(magic_cookie));
		w_report_error(globals.err_buff,__FILE__,__LINE__,__func__,0,1,error);
	}
	else
	{
		buff = magic_file(magic_cookie, arg);
		len = strlen(buff);
		magic_full = realloc(magic_full,(len+1)*sizeof(char));
		strncpy(magic_full,buff,len);
		magic_full[len] = '\0';
		magic_close(magic_cookie);
	}
	return (const char*) magic_full;
}
#endif

/* copy (arg) to (dst) checking the len (max_len) and preserving the const attribute. */
void w_argcpy(const char **dst, const char *arg, size_t max_len, const char *file, int line_no, const char *func)
{
	char *tmp;
	size_t arg_len;

	if(arg == NULL)
		w_report_error("called with NULL argument.",file,line_no,__func__,0,1,error);
	else if( (arg_len=strlen(arg)) > max_len )
	{
		snprintf(globals.err_buff,MAX_BUFF,"argument for function \"%s\", is more then %d chars.",func,(int)max_len);
		w_report_error(globals.err_buff,file,line_no,__func__,0,0,error);
		w_report_error("security breach.",file,line_no,__func__,0,1,error);
	}
	else
	{
		tmp = malloc((arg_len+1)*sizeof(char));
		strncpy(tmp,arg,arg_len);
		tmp[arg_len] = '\0';
		if( *dst != NULL)
			free((void *) *dst);
		*dst = tmp;
	}

	return;
}

/* return a pointer to the t_info struct of the calling thread */
t_info *w_find_myself(char *file, int line_no)
{
	t_info *ttmp = NULL;
	pthread_t thread_id = pthread_self();

	pthread_mutex_lock(&pool_lock);
	for(ttmp=globals.tpool;ttmp!=NULL && ttmp->thread != thread_id;ttmp=ttmp->next);
	pthread_mutex_unlock(&pool_lock);
	if(ttmp==NULL)
		w_report_error("cannot find myself in the thread pool.",file,line_no,__func__,0,1,error);
	return ttmp;
}

/* cleanup function for thread_wait */
static void wait_cleanup(void *garbage)
{
	pthread_mutex_unlock(&pool_lock);
}

/* wait for a thread before start */
static void *thread_wait(void *arg)
{
	struct input_args {
		void *(*func)(void*);
		void *args;
		pthread_t wait;
		};
	void *tmp_arg = ((struct input_args*)arg)->args;
	void *(*func_ptr)(void *) = ((struct input_args*)arg)->func;
	t_info *self = NULL;
	pthread_t wait = ((struct input_args*)arg)->wait;

	free(arg);

	//fetch myself in the waiting phase
	self = w_find_myself(__FILE__,__LINE__);

	pthread_cleanup_push(wait_cleanup,NULL);
	while(pthread_kill(wait,0)==0)
	{
		pthread_mutex_unlock(&pool_lock);
		usleep(10 * 1000);
		pthread_mutex_lock(&pool_lock);
	}
	/* change our state to running */
	if(self!=NULL)
		self->status = running;
	pthread_mutex_unlock(&pool_lock);
	pthread_cleanup_pop(0);
	/* execute function */
	pthread_exit((*func_ptr)(tmp_arg));
}

/* cleanup function for thread_wait_first */
static void wait_first_cleanup(void *arg)
{
	pthread_mutex_unlock(&pool_lock);
}

/* wait for any thread that finish then start */
static void *thread_wait_first(void *arg)
{
	int run_before,run_now;
	t_info *self=NULL,*ttmp=NULL;
	struct input_args {
		void *(*func)(void*);
		void *args;
		};
	void *(*func_ptr)(void *) = ((struct input_args *)arg)->func;
	void *tmp_arg = ((struct input_args *)arg)->args;
	free(arg);
	pthread_cleanup_push(wait_first_cleanup,NULL);

	pthread_mutex_lock(&pool_lock);
	// count how many threads are running
	for(run_before=0,ttmp=globals.tpool;ttmp!=NULL;ttmp=ttmp->next)
	{
		if(ttmp->status == running)
			run_before++;
		else if(pthread_equal(pthread_self(),ttmp->thread))
			self = ttmp;
	}

	pthread_mutex_unlock(&pool_lock);

	if(self==NULL)
		w_report_error("cannot find myself in the thread pool.",__FILE__,__LINE__,__func__,0,1,error);

	run_now=run_before;

	usleep(100 * 1000);

	while(run_now>=run_before)
	{
		pthread_mutex_unlock(&pool_lock);
		usleep(10 * 1000);
		pthread_mutex_lock(&pool_lock);
		for(run_now=0,ttmp=globals.tpool;ttmp!=NULL;ttmp=ttmp->next)
			if(ttmp->status == running)
				run_now++;
	}
	self->status = running;
	pthread_mutex_unlock(&pool_lock);
	pthread_cleanup_pop(0);
	pthread_exit((*func_ptr)(tmp_arg));
}

/* launch a new thread that execute (func) with (arg)
 * if a (wait) thread is given the spawned one will wait until the first end.
 * if running threads number overclimb the number of processors,
 * the spawned thread will wait until anyone of the others threads finish.
 */
struct t_info *w_spawn_thread(void *(*func)(void*), void *arg, t_info *wait, const char *file, int line_no)
{
	int num,run;
	static int cores=-1;
	struct wait_struct {
		void *(*func)(void*);
		void *args;
		pthread_t wait;
		} *wait_args;
	struct t_info *ttmp=NULL,*told=NULL;

	if(cores==-1) // first call
		cores = get_n_cpus();
	pthread_mutex_lock(&pool_lock);

	for(run=num=0,ttmp=globals.tpool;ttmp!=NULL;num++,told=ttmp,ttmp=ttmp->next)
		if(ttmp->status == running)
			run++;

	if(num>=MAX_THREADS)
	{
		w_report_error("max number of threads reached.",file,line_no,__func__,0,0,error);
		pthread_mutex_unlock(&pool_lock);
		return NULL;
	}
	else if(told==NULL) // this is the first thread
		globals.tpool = ttmp = w_malloc(sizeof(t_info),__FILE__,__LINE__);
	else
		ttmp = told->next = w_malloc(sizeof(t_info),__FILE__,__LINE__);

	if(wait==NULL)
	{
		if(run < cores)
		{
			ttmp->status = running;
			pthread_create(&(ttmp->thread),NULL,func, (void *) arg);
		}
		else
		{
			ttmp->status = waiting;
			wait_args = w_malloc(sizeof(struct wait_struct),__FILE__,__LINE__);
			wait_args->func = func;
			wait_args->wait = 0; // just wait for the first done thread
			wait_args->args = arg;
			pthread_create(&(ttmp->thread), NULL, thread_wait_first, (void *) wait_args);
		}
	}
	else
	{
		ttmp->status = waiting;
		wait_args = w_malloc(sizeof(struct wait_struct),__FILE__,__LINE__);
		wait_args->func = func;
		wait_args->wait = wait->thread;
		wait_args->args = arg;
		pthread_create(&(ttmp->thread),NULL,thread_wait,(void *) wait_args);
	}
	pthread_mutex_unlock(&pool_lock);
	return ttmp;
}

/* this function is useful for use libCurl, check libCurl docs. */
static size_t memory_writer(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct _mem
	{
		char *memory;
		size_t size;
	} *mem = (struct _mem *)userp;

	while((mem->memory = realloc(mem->memory, mem->size + realsize + 1)) == NULL && errno == EINPROGRESS )
		usleep(10);
	if (mem->memory == NULL)
		w_report_error("memory_writer()",__FILE__,__LINE__,__func__,1,1,error);

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

/* destroy ANYTHING, also the threads */
void destroy_all()
{
	_hash *tmp=NULL,*old=NULL;
	struct t_info *ttmp=NULL,*told=NULL;
	_wpa *wold=NULL,*wtmp=NULL;
	int i,n_sleep=0;
	bool force_shutdown = false;

	//use i for store maximum loop count
	i = TKILL_TIMEOUT * 100;
	// first of all kill our childs
	for(ttmp=globals.tpool;ttmp!=NULL;)
	{
		if(ttmp->result != NULL)
			free(ttmp->result);
		if(ttmp->thread!=0)
		{
			for(pthread_cancel(ttmp->thread);pthread_kill(ttmp->thread,0)==0 && n_sleep < i;n_sleep++)
				usleep(10);
			if(n_sleep == i)
			{
				/* skip mutex lock, maybe zombie thread is waiting on that mutex and will block us too */
				snprintf(globals.err_buff,MAX_BUFF,"could not kill child with LWPID=%lu.",(unsigned long int) ttmp->thread);
				w_report_error(globals.err_buff,__FILE__,__LINE__,__func__,0,0,error);
				force_shutdown = true;
			}
			else
				pthread_join(ttmp->thread,NULL);
		}
		told=ttmp;
		ttmp=ttmp->next;
		free((void *) told);
	}

	// destroy (char *) if they exist
	if(globals.err_buff!= NULL)
		free((void *) globals.err_buff);
	if(globals.outfile != NULL)
		free((void *) globals.outfile);
	if(globals.wordlist != NULL)
		free((void *) globals.wordlist);
	if(globals.hccap != NULL)
	{
		if(remove(globals.hccap) != 0)
			w_report_error(globals.hccap,__FILE__,__LINE__,__func__,1,0,error);
		free((void *) globals.hccap);
	}
	if(globals.pcap != NULL)
	{
		if(remove(globals.pcap) != 0)
			w_report_error(globals.pcap,__FILE__,__LINE__,__func__,1,0,error);
		free((void *) globals.pcap);
	}

	// destroy hash_list
	for(tmp=globals.hash_list;tmp != NULL;)
	{
		old = tmp;
		tmp=tmp->next;
		if(old->hash != NULL)
			free((void *) old->hash);
		if(old->plain != NULL)
			free((void *) old->plain);
		free(old);
	}

	for(wtmp=globals.wpa_list;wtmp!=NULL;wtmp=wtmp->next,free_wpa(wold))
		wold=wtmp;
#ifdef HAVE_LIBMAGIC
	w_get_mime(NULL,__FILE__,__LINE__);
#endif

	//reset globals in order to prevent double frees if recalled ( shouldn't happend )
	i = globals.log_level;
	memset(&globals,0,sizeof(struct _globals));
	globals.log_level = i;

	//if a child cannot be killed, suicide
	if(force_shutdown == true)
	{
		w_report_error("karakiri for make sure killing childs.",__FILE__,__LINE__,__func__,0,0,verbose);
		raise(SIGTERM); // kaboom
	}
	return;
}

void signal_handler(int signum)
{
	w_report_error("recieved SIGINT.",__FILE__,__LINE__,__func__,0,1,error);
	//if we are here after a 'fatal' report something horrible is happend, so suicide.
	raise(SIGTERM);
}