/*
 *	Autohack - automatically hack everything
 *	Copyright (C) 2012  Massimo Dragano <massimo.dragano@gmail.com>,
 * Andrea Columpsi <andrea.columpsi@gmail.com>
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
#ifndef HEADER_H
#define HEADER_H

/* envinroment check */
#ifdef HAVE_CONFIG_H
#	include "config.h"
#	ifndef HAVE_FNMATCH
#		error "this system havn't fnmatch.h"
#	endif
#	ifndef HAVE_WORKING_FORK
#		error	"this system havn't fork() O_o"
#	endif
#	if HAVE_MALLOC != 1
#		error	"this system havn't malloc() O_o"
#	endif
#	if HAVE_REALLOC != 1
#		error	"this system havn't realloc() O_o"
#	endif
#	ifndef HAVE_DIRENT_H
#		error	"this system havn't dirent.h"
#	endif
#	ifndef HAVE_SYS_TYPES_H
#		error	"this system havn't sys/types.h O_o"
#	endif
#	ifndef HAVE_NETINET_IN_H
#		error	"this system havn't netinet/in.h"
#	endif
#	ifndef HAVE_NETDB_H
#		error	"this system havn't netdb.h"
#	endif
#	ifndef HAVE_STDBOOL_H
#		ifndef HAVE__BOOL
#			ifdef __cplusplus
typedef bool _Bool;
#			else
#				define _Bool signed char
#			endif
#		endif
#		define bool _Bool
#		define false 0
#		define true 1
#	else
#		include <stdbool.h>
#	endif
#	ifndef STDC_HEADERS
#		error	"this system havn't string.h O_o"
#	endif
#	ifndef HAVE_UNISTD_H
#		error	"this system havn't unistd.h ( maybe windows ? )"
#	endif
#	ifndef HAVE_SYS_WAIT_H
#		error	"this system havn't sys/wait.h"
#	endif
#	ifdef TIME_WITH_SYS_TIME
# 	include <sys/time.h>
# 	include <time.h>
#	else
# 	ifdef HAVE_SYS_TIME_H
#  		include <sys/time.h>
# 	else
#  		include <time.h>
# 	endif
#	endif
#	ifdef HAVE_TERMIOS_H
# 	include <termios.h>
#	elifndef GWINSZ_IN_SYS_IOCTL
#		error "this system havn't TIOCGWINSZ"
#	endif
#	ifndef HAVE_SYS_SOCKET_H
#		error "this system havn't sys/socket.h O_o"
#	endif
#	ifndef HAVE_REGEX_H
#		error "this system havn't regex.h"
#	endif
#	ifndef HAVE_STDLIB_H
#		error "this system havn't stdlib.h O_o"
#	endif
#	ifndef HAVE_STRING_H
#		error "this system havn't string.h O_o"
#	endif
#	ifndef HAVE_LIBCURL
#		error "this system havn't libcurl installed"
#	endif
#	ifndef HAVE_LIBCRYPTO
#		error "this system havn't crypto libs"
#	endif
#	ifndef HAVE_LIBPTHREAD
#		error "this system havn't pthread.h O_o"
#	endif
#	ifdef STAT_MACROS_BROKEN
#		error	"bad stat macros. ( Tektronix UTekV, Amdahl UTS and Motorola System V/88 )"
#	endif
#else
#	error		"no config.h, ./configure script not executed or failed."
#endif/* HAVE_CONFIG_H */

/* include headers needed for our types declarations */
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/param.h>

/* defines */
#define MAX_BUFF 				(PATH_MAX)
#define MAX_LINE				255
#define TKILL_TIMEOUT		100 // ms
#ifndef MAX_INTERFACES // maximum number of network interfaces
#	define MAX_INTERFACES 20
#endif
#ifndef MAX_THREADS
#	define MAX_THREADS 20
#endif
#define uchar unsigned char

/* data structs */
enum _log_level
{
	quiet,
	error,
	warning,
	info,
	verbose,
	verbose2,
	verbose3,
	debug
};

#define N_TYPE 11

typedef enum _hash_type
{
	NONE,
	LM,
	md5,
	MYSQL3,
	MYSQL,
	NT,
	sha1,   // ...must use lowercase here,
	sha256, // or openssl will joke you.
	sha384,
	sha512,
	UNKNOWN
} hash_type;

static const char* hash_type_str[] =
{
	"NONE",
	"LM",
	"MD5",
	"MYSQL3",
	"MYSQL",
	"NT",
	"SHA1",
	"SHA256",
	"SHA384",
	"SHA512",
	"UNKNOWN"
};

static const char* type_rgx[] =
{
	".*",
	"^[0-9A-Fa-f]{32}$",
	"^[0-9A-Fa-f]{32}$",
	"^[0-9A-Fa-f]{16}$",
	"^[0-9A-Fa-f]{40}$",
	"^[0-9A-Fa-f]{32}$",
	"^[0-9A-Fa-f]{40}$",
	"^[0-9A-Fa-f]{64}$",
	"^[0-9A-Fa-f]{98}$",
	"^[0-9A-Fa-f]{128}$",
	".*"
};

enum _status { done, running, waiting, parsed, killed }; // thread status ( i forgot what parsed means )

typedef struct _hash
{
	unsigned int id;
	hash_type type;
	char *hash,*plain;
	pthread_mutex_t lock;
	struct _hash *next;
} _hash;

// hashcat capture structure
typedef struct
{
	char          essid[36];

	unsigned char mac1[6];
	unsigned char mac2[6];
	unsigned char nonce1[32];
	unsigned char nonce2[32];

	unsigned char eapol[256];
	int           eapol_size;

	int           keyver;
	unsigned char keymic[16];

} hccap_t;

typedef struct _wpa
{
	unsigned int id;
	char *essid,*key;
	hccap_t *hccap;
	struct _wpa *next;
}_wpa;

typedef struct _iface
{
	unsigned int id;
	const char *name,*path;
	char *internal_name;
	struct _iface *next;
}_iface;

//N3tAug3r should fill the following 2 structs
typedef struct _subnet
{
	char *address;
	_iface *iface;
	struct _subnet *next;
}_subnet;

typedef struct _host
{
	unsigned int id;
	char *address,*name;
	_subnet *subnet;
	struct _host *next;
}_host;

typedef struct
{
	unsigned int number;
	char *name;
	enum _status status;
}_state;

typedef struct t_info
{
	void *result;
	_state *owner;
	pthread_t 	thread;
	enum _status status;
	pthread_mutex_t lock;
	struct t_info *next;
} t_info;

enum _method {GET,POST};

struct _cmd_opts {
	bool online,dict,passive;
};

/* this is the main container for shared data
 * log_level is the current logging level
 * options is the user providded options
 * err_buff is the buffer user in reporting subroutines
 * outfile is the name of the output file, if any.
 * hccap is the name of the temporary hccap sniffing file ( for WPA handshakes ).
 * wordlist is the name of the wordlist file.
 * pcap is the name of the temporary pcap sniffing file.
 * wpa_list is the list of found WPA handshakes ? or sorrounding AP ?
 * cur_wpa is the current focused WPA.
 * hash_list is the list of the founded hashes.
 * cur_hash is the current focused hash.
 * host_list is the list of the founded hosts.
 * cur_host is the current focused host.
 * subnet_list is the list of the founded subnets.
 * cur_subnet is the current focused subnet.
 * iface_list is the list of the founded network interfaces.
 * TODO: add epxloit_list
 * err_buff_lock is the mutex that prevent multiple threads access to error buffer at the same time.
 * tpool is the global thread pool.
 */
struct _globals {
	enum _log_level log_level;
	struct _cmd_opts options;
	char *err_buff;
	const char *outfile, *hccap, *wordlist, *pcap;
	_wpa *wpa_list, *cur_wpa;
	_hash *hash_list,*cur_hash;
	_host *host_list,*cur_host;
	_subnet *subnet_list,*cur_subnet;
	_iface *iface_list;
	pthread_mutex_t err_buff_lock;
	t_info *tpool;
};

/* global data */
// threads pool mutex
pthread_mutex_t pool_lock;
//global data contaner
struct _globals globals;

/* prototypes */
/* from common.c */
void w_report_error(const char *, const char *, int , const char *, int , int , enum _log_level );
int mysend(int , const char *, long );
int w_socket(int , int , int , const char *, int );
int w_bind(int , struct sockaddr *, socklen_t , const char *, int );
int w_listen(int , int , const char *, int );
void *w_malloc(size_t , const char *, int );
void w_tmpnam(char *,const char *, int , const char *);
char *w_regexp(const char *, const char *, size_t , const char *, int , const char *);
int get_n_cpus();
char *w_digest(unsigned char *, /*char *,*/hash_type , const char *, int );
char *w_str2low(const char *,const char *,int );
char *w_str2up(const char *,const char *,int );
void w_write_out(_hash *, _wpa *, const char *, int , const char *);
void w_add_hash( hash_type ,const char *, const char *, int );
void w_del_hash(_hash *, const char *, int );
void w_add_hash_plain(_hash *, char *, struct t_info *, char *, const char *, int );
void w_add_iface( char *, char *, int, const char *);
void w_del_iface( _iface *, char *, int, const char *);
void free_iface(_iface *);
void print_lists();
void print_type_list();
char *find_file(const char *, const char *);
char *w_get_full_path( const char *, const char *,int ,const char *);
void w_add_wpa(char *, hccap_t *, const char *, int );
bool test_wpa_key(hccap_t *, char *);
void free_wpa(_wpa *);
char *w_fgets_fix(char *, const char *, int , const char *);
const char *w_get_mime(const char *, const char *, int);
void w_argcpy(const char **, const char *, size_t , const char *, int, const char *);
t_info *w_find_myself(char *,int);
static void wait_cleanup(void *);
static void *thread_wait(void *);
static void wait_first_cleanup(void *);
static void *thread_wait_first(void *);
struct t_info *w_spawn_thread(void *(*)(void*), void *, t_info *, const char *, int );
static size_t memory_writer(void *, size_t , size_t , void *);
void destroy_all();
void signal_handler(int signum);
/* from init.c */
void init(int,char**);
void check_whoami();
void fill_iface_list();

/* macros */
#ifndef COMMON_H
#define regexpn(s,r,n)									(w_regexp((s),(r),(n+1),__FILE__,__LINE__,__func__))
#define regexp(s,r)											(w_regexp((s),(r),1,__FILE__,__LINE__,__func__))
#define wpa_write_out(w)								(w_write_out(NULL,(w),__FILE__,__LINE__,__func__))
#define hash_write_out(h)								(w_write_out((h),NULL,__FILE__,__LINE__,__func__))
#define fflush(s)												({if(isatty(fileno((s)))){fflush((s));}})
#define socket(domain, type, protocol) 	(w_socket((domain),(type),(protocol),__FILE__,__LINE__))
#define listen(sockfd, backlog) 				(w_listen((sockfd),(backlog),__FILE__,__LINE__))
#define bind(sockfd, addr, len) 				(w_bind((sockfd),(addr),(len),__FILE__,__LINE__))
#define malloc(bytes) 									(w_malloc((bytes),__FILE__,__LINE__))
#define add_hash(type,hash) 						(w_add_hash((type),(hash),__FILE__,__LINE__))
#define del_hash(h) 										(w_del_hash((h),__FILE__,__LINE__))
#define get_mime(f)											(w_get_mime((f),__FILE__,__LINE__))
#define argcpy(d,s,l)										(w_argcpy((d),(s),(l),__func__,__FILE__,__LINE__))
#define str2low(s) 											(w_str2low((s),__FILE__,__LINE__))
#define str2up(s)												(w_str2up((s),__FILE__,__LINE__))
#define fgets_fix(s)										(w_fgets_fix((s),__FILE__,__LINE__,__func__))
#define tspawn_wait(a,f,w)							(w_thread_spawn((a),(f),(w),__FILE__,__LINE__))
#define tspawn(a,f)											(w_thread_spawn((a),(f),NULL,__FILE__,__LINE__))
#define find_myself()										(w_find_myself(__FILE__,__LINE__))
#define get_full_path(f)								(w_get_full_path((f),__FILE__,__LINE__,__func__))
#define tmpnam(s)												(w_tmpnam((s),__FILE__,__LINE__,__func__))
#define add_wpa(e,h)										(w_add_wpa((e),(h),__FILE__,__LINE__))
#define add_wpa_key(t,k)								(w_add_wpa_key((t),(k),__FILE__,__LINE__))
#define add_hash_plain(h,hsh,t,p)				(w_add_hash_plain((h),(hsh),(t),(p),__FILE__,__LINE__))
#define add_iface(n)										(w_add_iface((n),__FILE__,__LINE__,__func__))
#define del_iface(i)										(w_del_iface((i),__FILE__,__LINE__,__func__))

/* report messages to console.
 * report will print the msg after formatting the (form) string with (args)
 * fatal will do the same, but it also exit with error and close the entire program.
 * print will print static strings, in order to avoid extra mutex locks.
 * if {fatal,report,print} have a 'p' before they will use perror for printing error message.
 */
#define report(log, form, args...)					_report(log,0,0,form,##args)
#define preport(log, form, args...)					_report(log,1,0,form,##args)
#define _report(log, p, f, form, args...)		{pthread_mutex_lock(&globals.err_buff_lock); snprintf(globals.err_buff,MAX_BUFF,form,##args); w_report_error(globals.err_buff,__FILE__,__LINE__,__func__,(p),(f),(log));pthread_mutex_unlock(&globals.err_buff_lock);}
#define fatal(msg)													w_report_error(msg,__FILE__,__LINE__,__func__,0,1,error)
#define pfatal(msg)													w_report_error(msg,__FILE__,__LINE__,__func__,1,1,error)
#define print(log,msg)											w_report_error(msg,__FILE__,__LINE__,__func__,0,0,log)
#define pprint(log,msg)											w_report_error(msg,__FILE__,__LINE__,__func__,1,0,log)
#endif /* COMMON_H */
#endif /* HEADER_H */