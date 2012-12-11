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
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "header.h"

int main(int argc, char **argv)
{
	init(argc,argv);
	print_lists();
	sleep(10); /* ALL YOUR CODE GOES HERE */
	exit(EXIT_SUCCESS);
}