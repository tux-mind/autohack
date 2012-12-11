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
	globals.log_level = debug; // set log level
	print(debug,NULL); // set main thread id
	signal(SIGINT, signal_handler);
	check_whoami();
	fill_iface_list();
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