AC_INIT([autohack], [0.0.0], [massimo.dragano@gmail.com, andrea.columpsi.com],,[https://github.com/tux-mind/autohack])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_PROG_CC
AM_PROG_CC_C_O
AC_FUNC_FNMATCH
AC_FUNC_FORK
AC_HEADER_DIRENT
AC_HEADER_RESOLV
AC_HEADER_STAT
AC_HEADER_STDBOOL
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_HEADER_TIME
AC_HEADER_TIOCGWINSZ
AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([regex.h])
AC_CHECK_HEADERS([sys/statvfs.h])
AC_CHECK_LIB([pthread],[main])
AC_CHECK_LIB([curl],[main])
AC_CHECK_LIB([crypto],[main])
AC_CHECK_LIB([magic],[main])

debug_default="yes"
AC_ARG_ENABLE(debug, [  --enable-debug=[no/YES] write debugging symbols and turn off optimization.],enable_debug=$enableval, enable_debug=$debug_default)
if test "x$enable_debug" == "xyes"; then
	CFLAGS="$CFLAGS -ggdb -O0"
	#AC_MSG_RESULT([yes])
else
	CFLAGS="$CFLAGS -O2 -ffast-math -fomit-frame-pointer -pipe"
	#AC_MSG_RESULT([no])
fi
AC_DEFUN([AC_SET_DEFAULT_PATHS_SYSTEM],
[AC_REQUIRE([AC_CANONICAL_HOST]) # --------------------------------------------
case "$prefix:$ac_default_prefix" in
  NONE:/usr/local)
    result=""
    AC_MSG_CHECKING(default prefix path)
    case "${target_os}" in
      *cygwin* | *mingw* | *uwin* | *djgpp | *emx* )
        if test "${host_os}" = "${target_os}" ; then
           ac_default_prefix="/programs"
           result="(win/dos target)"
        else
           case "$PATH" in
              *:/usr/local/cross-tools/$target_alias/bin:*)
                  ac_default_prefix="/usr/local/cross-tools/$target_alias" ;;
              *:/usr/local/$target_alias/bin:*)
                  ac_default_prefix="/usr/local/$target_alias" ;;
              *:/usr/local/$target_cpu-$target_os/bin:*)
                  ac_default_prefix="/usr/local/$target_cpu-$target_os" ;;
              *)
                  ac_default_prefix="/programs" ;;
           esac
           result="(win/dos cross-compiler)"
        fi
    ;;
    esac
    AC_MSG_RESULT($ac_default_prefix $result)
  ;;
esac
AC_MSG_CHECKING(default prefix system)
result="$prefix" ; test "$result" = "NONE" && result="$ac_default_prefix"
case ${result} in
  /programs | /programs/*) result="is win-/programs"
     # on win/dos, .exe .dll and .cfg live in the same directory
     libdir=`echo $libdir |sed -e 's:^..exec_prefix./lib$:${bindir}:'`
     sbindir=`echo $sbindir |sed -e 's:^..exec_prefix./sbin$:${libdir}:'`
     sysconfdir=`echo $sysconfdir |sed -e 's:^..prefix./etc$:${sbindir}:'`
     libexecdir=`echo $libexecdir |sed -e 's:/libexec$:/system:'`
     # help-files shall be set with --infodir, docprefix is datadir
     docprefix="${datadir}"
     mandir=`echo $mandir \
                             |sed -e 's:^..prefix./man$:${datadir}/info:'`
     includedir=`echo $includedir \
                |sed -e 's:^..prefix./include$:${datadir}/include:'`
     # other state files (but /etc) are moved to datadir
     sharedstatedir=`echo $sharedstatedir \
                     |sed -e 's:^..prefix./com$:${datadir}/default:'`
     localstatedir=`echo $localstatedir \
                     |sed -e 's:^..prefix./var$:${datadir}/current:'`
  ;;
  /usr) result="is /usr-shipped"
     # doc files are left at prefix
     docprefix="${prefix}"
     # state files go under /top
     sysconfdir=`echo $sysconfdir |sed -e 's:^..prefix./etc$:/etc:'`
     sharedstatedir=`echo $sharedstatedir \
                     |sed -e 's:^..prefix./com$:/etc/default:'`
     # $prefix/var is going to end up in /var/lib
     localstatedir=`echo $localstatedir \
                     |sed -e 's:^..prefix./var$:/var/lib:'`
  ;;
  /opt | /opt/*) result="is /opt-package"
     # state files go under /top/prefix
     sysconfdir=`echo $sysconfdir \
                     |sed -e 's:^..prefix./etc$:/etc${prefix}:'`
     sharedstatedir=`echo $sharedstatedir \
                     |sed -e 's:^..prefix./com$:/etc/default${prefix}:'`
     # $prefix/var is going to to be /var$prefix... once again
     localstatedir=`echo $localstatedir \
                     |sed -e 's:^..prefix./var$:/var${prefix}:'`
     # doc files are left at prefix
     docprefix="${prefix}"
  ;;
  *) result="is /local-package"
     # doc files are moved from prefix down to datadir
     docprefix="${datadir}"
     mandir=`echo $mandir \
                     |sed -e 's:^..prefix./man$:${datadir}/man:'`
     infodir=`echo $infodir \
                     |sed -e 's:^..prefix./infodir$:${datadir}/info:'`
     # never use $prefix/com - that is no good idea
     sharedstatedir=`echo $sharedstatedir \
                     |sed -e 's:^..prefix./com$:${sysconfdir}/default:'`
     sysconfdir=`echo $sysconfdir |sed -e 's:^..prefix./etc$:/etc:'`
  ;;
esac
AC_MSG_RESULT($result)
# --------------------------------------------------------
])


AC_SET_DEFAULT_PATHS_SYSTEM
CONFDIR="$ac_default_prefix$sysconfdir/autohack"
AC_DEFINE_UNQUOTED([CONFDIR],"$CONFDIR","config dir")
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
