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
#include "init.h"

void init(int argc, char **argv)
{
	atexit(destroy_all);
	memset(&globals,0,sizeof(struct _globals));
	globals.err_buff = malloc(MAX_BUFF*sizeof(char)); // alocate error buffer
	globals.log_level = info; // default log_level to info
	globals.options.dict = globals.options.online = globals.options.passive = true;
	print(debug,NULL); // set main thread id
	signal(SIGINT, signal_handler);
	option_preparser(argc,argv);
	check_whoami();
	fill_iface_list();
	option_parser(argc,argv);
	report(debug,"global command line: online=0x%x; dict=0x%x; passive=0x%x;",globals.options.online,globals.options.dict,globals.options.passive);
}

void check_whoami()
{
	if(getuid() != 0)
		fatal("we are not root!");
}

void fill_iface_list()
{
	int sock,interfaces,i;
	struct ifconf ifconf;
	struct ifreq ifreq[MAX_INTERFACES];

	sock = socket(AF_INET, SOCK_STREAM, 0);
	ifconf.ifc_buf = (char *) ifreq;
	ifconf.ifc_len = sizeof(ifreq);
	if(ioctl(sock, SIOCGIFCONF, &ifconf) == -1)
		pfatal("ioctl(SIOCGIFCONF)");
	interfaces = ifconf.ifc_len / sizeof(struct ifreq);
	for(i = 0; i < interfaces; i++)
		add_iface(ifreq[i].ifr_name);
}

/* print help */
void usage(char *prog_name)
{
	const char *msg_fmt =
	"%s [-optionsgoeshere] [argshere]\n"
	"\n"
	"automatically hack everithing.\n"
	"\n"
	"options:\n"
	"\t-h\tprint this message\n"
	"\t-o\toutfile\n"
	"\t-w\twordlist\n"
	"\t-p\tdisable passive mode\n"
	"\t-d\tskip dictionary attacks\n"
	"\t-l\tdisable online features\n"
	"\t-v\tincrease verbosity level\n"
	"\t-D\tenable debuging output\n"
	"\t-q\tbe quiet\n"
	"\n"
	"Developed by:\n"
	"\tMassimo Dragano <massimo.dragano@gmail.com>\n"
	"\tAndrea Columpsi <andrea.columpsi@gmail.com>\n"
	"\n"
	"%s - v0.0.0\n";

	printf(msg_fmt,prog_name,prog_name);
}

/* preparsing command line for flags and early-exit conditions */
void option_preparser(int argc, char **argv)
{
	bool 	want_exit = false,
					bad_opts = false;
	int c;
	/* what about no options given? for now threat as normal behaviour */
	while((c = getopt(argc,argv,"o:w:hpldvqD")) != -1)
	{
			switch(c)
			{
				case 'h':
					usage(argv[0]);
					want_exit = true;
					break;
				case 'd':
					globals.options.dict = false;
					break;
				case 'p':
					globals.options.passive = false;
					break;
				case 'l':
					globals.options.online = false;
					break;
				case 'v':
					if(globals.log_level < verbose3)
						globals.log_level++;
					else if(globals.log_level == debug)
						print(info,"already in debug mode.");
					else
						print(warning,"maximum verbose level reached, try with -D for debug output");
					break;
				case 'D':
					globals.log_level = debug;
					break;
				case 'q':
					if(globals.log_level > info)
						globals.log_level -= info;
					else
						globals.log_level = quiet;
					break;
				case 'o':
				case 'w':
					break;
				default:
					bad_opts = true; // getopt alrready prints something.
					break;
			}
	}
	if(bad_opts)
	{
		/*if want_exit == true means that user have yet seen what he want see.
		 * e.g. usage or supported hash types
		 */
		if(!want_exit)
			usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	else if(want_exit)
		exit(EXIT_SUCCESS);
	optind = 1;//reset option index
}

/* parsing command line arguments */
void option_parser(int argc, char **argv)
{
	int c;

	while((c = getopt(argc,argv,"o:w:hpldvqD")) != -1)
	{
		switch(c)
		{
			case 'o':
				parser_outfile(optarg);
				break;
			case 'w':
				parser_wordlist(optarg);
				break;
			default:
				break;
		}
	}
	optind = 1; // reset option index
}