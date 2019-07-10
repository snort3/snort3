#!/bin/sh -e
#
# Init.d script for Snort in Debian
#
# Copyright (c) 2001 Christian Hammers 
# Copyright (c) 2001-2002 Robert van der Meulen
# Copyright (c) 2002-2004 Sander Smeenk <ssmeenk@debian.org>
# Copyright (c) 2004-2012 Javier Fernandez-Sanguino <jfs@debian.org>
#
# This is free software; you may redistribute it and/or modify
# it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2,
# or (at your option) any later version.
#
# This is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License with
# the Debian operating system, in /usr/share/common-licenses/GPL;  if
# not, write to the Free Software Foundation, Inc., 59 Temple Place,
# Suite 330, Boston, MA 02111-1307 USA
#
### BEGIN INIT INFO
# Provides:          snort
# Required-Start:    $time $network $local_fs $remote_fs
# Required-Stop:     $network $remote_fs
# Should-Start:      $syslog
# Should-Stop:       
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Lightweight network intrusion detection system
# Description:       Intrusion detection system that will
#                    capture traffic from the network cards and will
#                    match against a set of known attacks.
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

test $DEBIAN_SCRIPT_DEBUG && set -v -x

DAEMON=/usr/sbin/snort
NAME=snort
DESC="Network Intrusion Detection System"

. /lib/lsb/init-functions


CONFIG=/etc/snort/snort.debian.conf
# Old (obsolete) way to provide parameters
if [ -f /etc/snort/snort.common.parameters ] ; then
	COMMON=`cat /etc/snort/snort.common.parameters`
elif [ -r /etc/default/snort ] ; then
# Only read this if the old configuration is not present
	. /etc/default/snort
	COMMON="$PARAMS -l $LOGDIR -u $SNORTUSER -g $SNORTGROUP"
fi

test -x $DAEMON || exit 0
test -f $CONFIG && . $CONFIG
test -z "$DEBIAN_SNORT_HOME_NET" && DEBIAN_SNORT_HOME_NET="192.168.0.0/16"

# to find the lib files
cd /etc/snort

running()
{
        PIDFILE=$1
# No pidfile, probably no daemon present
        [ ! -f "$PIDFILE" ] && return 1
        pid=`cat $PIDFILE`
# No pid, probably no daemon present
        [ -z "$pid" ] && return 1
        [ ! -d /proc/$pid ] &&  return 1
        cmd=`cat /proc/$pid/cmdline | tr "\000" "\n"|head -n 1 |cut -d : -f 1`
# No daemon
        [ "$cmd" != "$DAEMON" ] &&  return 1
        return 0
}


check_log_dir() {
# Does the logging directory belong to Snort?
	# If we cannot determine the logdir return without error
	# (we will not check it)
	# This will only be used by people using /etc/default/snort
	[ -n "$LOGDIR" ] || return 0
	[ -n "$SNORTUSER" ] || return 0
	if [ ! -e "$LOGDIR" ] ; then
		log_failure_msg "ERR: logging directory $LOGDIR does not exist"
		return 1
	elif [ ! -d "$LOGDIR" ] ; then
		log_failure_msg "ERR: logging directory $LOGDIR does not exist"
		return 1
	else
		real_log_user=`stat -c %U $LOGDIR`
	# An alternative way is to check if the snort user can create 
	# a file there...
		if [ "$real_log_user" != "$SNORTUSER" ] ; then
			log_failure_msg "ERR: logging directory $LOGDIR does not belong to the snort user $SNORTUSER"
			return 1
		fi
	fi
	return 0
}

check_root()  {
    if [ "$(id -u)" != "0" ]; then
        log_failure_msg "You must be root to start, stop or restart $NAME."
        exit 4
    fi
}

case "$1" in
  start)
        check_root
	log_daemon_msg "Starting $DESC " "$NAME"

        if ! check_log_dir; then
		log_failure_msg " will not start $DESC!"
		exit 5
	fi
	if [ "$DEBIAN_SNORT_STARTUP" = "dialup" ]; then
		shift
		set +e
		/etc/ppp/ip-up.d/snort "$@"
		ret=$?
                if  [ $ret -eq 0 ] ; then
                  log_end_msg 0
                else
                  log_end_msg 1
                fi
		exit $ret
	fi

	# Usually, we start all interfaces
	interfaces="$DEBIAN_SNORT_INTERFACE"

	# If we are requested to start a specific interface...
	test "$2" && interfaces="$2"

        # If the interfaces list is empty stop (no error)
        if [ -z "$interfaces" ] ; then
            log_progress_msg "no interfaces configured, will not start"
            log_end_msg 0
            exit 0
        fi

	myret=0
	got_instance=0
	for interface in $interfaces; do
		got_instance=1
		log_progress_msg "($interface"

                # Check if the interface is available:
                # - only if iproute is available
                # - the interface exists 
                # - the interface is up
                if ! [ -x /sbin/ip ] || ( ip link show dev "$interface" >/dev/null 2>&1 && [ -n "`ip link show up "$interface" 2>/dev/null`" ] ) ; then

		PIDFILE=/var/run/snort_$interface.pid
                CONFIGFILE=/etc/snort/snort.$interface.conf

                # Defaults:
		fail="failed (check /var/log/daemon.log, /var/log/syslog and /var/log/snort/)"
                run="yes"

                if [ -e "$PIDFILE" ] && running $PIDFILE; then
                        run="no" 
                        # Do not start this instance, it is already runing
                fi

                if [ "$run" = "yes" ] ; then
                    if [ ! -e "$CONFIGFILE" ]; then
                        log_progress_msg "using /etc/snort/snort.conf"
                        CONFIGFILE=/etc/snort/snort.conf
                    else
                        log_progress_msg "using /etc/snort/snort.$interface.conf"
                    fi

                    set +e
                    /sbin/start-stop-daemon --start --quiet  \
                        --pidfile "$PIDFILE" \
                        --exec $DAEMON -- $COMMON $DEBIAN_SNORT_OPTIONS \
                        -c $CONFIGFILE \
                        -S "HOME_NET=[$DEBIAN_SNORT_HOME_NET]" \
                        -i $interface >/dev/null
                    ret=$?
                    case "$ret" in
			0)
                                log_progress_msg  "...done)"
				;;
			*)
				log_progress_msg "...ERROR: $fail)"
				myret=$(expr "$myret" + 1)
				;;
                     esac
                     # Change the pidfile permissions if it exists
                     [ -e "$PIDFILE" ] && chown $SNORTUSER:$SNORTGROUP $PIDFILE
                     set -e
                else
                        log_progress_msg "...already running)"
                fi

                else
                # What to do if the interface is not available
                # or is not up
                        if [ "$ALLOW_UNAVAILABLE" != "no" ] ; then 
                            log_progress_msg "...interface not available)"
                        else 
                            log_progress_msg "...ERROR: interface not available)"
                            myret=$(expr "$myret" + 1)
                        fi
                fi
	done

	if [ "$got_instance" = 0 ] && [ "$ALLOW_UNAVAILABLE" = "no" ]; then
		log_failure_msg "No snort instance found to be started!" >&2
		exit 6
	fi

        if  [ $myret -eq 0 ] ; then
            log_end_msg 0
        else
            log_end_msg 1
        fi
	exit $myret
	;;
  stop)
        check_root
        log_daemon_msg "Stopping $DESC " "$NAME"
    
	if [ "$DEBIAN_SNORT_STARTUP" = "dialup" ]; then
		shift
		set +e
		/etc/ppp/ip-down.d/snort "$@"
		ret=$?
                if  [ $ret -eq 0 ] ; then
                    log_end_msg 0
                else
                  log_end_msg 1
                fi
		exit $ret
	fi

	# Usually, we stop all current running interfaces
	pidpattern=/var/run/snort_*.pid

	# If we are requested to stop a specific interface...
	test "$2" && pidpattern=/var/run/snort_"$2".pid

	got_instance=0
        myret=0
	for PIDFILE in $pidpattern; do
		# This check is also needed, if the above pattern doesn't match
		test -f "$PIDFILE" || continue

		got_instance=1
		interface=$(basename "$PIDFILE" .pid | sed -e 's/^snort_//')

		log_progress_msg "($interface"

		set +e
                if [ ! -e "$PIDFILE" -o -r "$PIDFILE" ] ; then
# Change ownership of the pidfile
		    /sbin/start-stop-daemon --stop --retry 5 --quiet --oknodo \
			--pidfile "$PIDFILE" --exec $DAEMON >/dev/null
                    ret=$?
                    rm -f "$PIDFILE"
                    rm -f "$PIDFILE.lck"
                else
                     log_progress_msg "cannot read $PIDFILE"
                     ret=4
                fi
		case "$ret" in
			0)
                                log_progress_msg  "...done)"
				;;
			*)
				log_progress_msg "...ERROR)"
				myret=$(expr "$myret" + 1)
				;;
		esac
                set -e

	done

	if [ "$got_instance" = 0 ]; then
		log_warning_msg " - No running snort instance found"
                exit 0 # LSB demands we don't exit with error here
	fi
        if  [ $myret -eq 0 ] ; then
            log_end_msg 0
        else
            log_end_msg 1
        fi
	exit $myret
	;;
  restart|force-restart|reload|force-reload)
        check_root
	# Usually, we restart all current running interfaces
	pidpattern=/var/run/snort_*.pid

	# If we are requested to restart a specific interface...
	test "$2" && pidpattern=/var/run/snort_"$2".pid

	got_instance=0
	for PIDFILE in $pidpattern; do
		# This check is also needed, if the above pattern doesn't match
		test -f "$PIDFILE" || continue

		got_instance=1
		interface=$(basename "$PIDFILE" .pid | sed -e 's/^snort_//')
		$0 stop $interface || true
		$0 start $interface || true
	done

        # If we did not find any instance of Snort then we restart all
	if [ "$got_instance" = 0 ]; then
                $0 start
	fi
	;;
  status)
# Non-root users can use this (if allowed to)
        log_daemon_msg "Status of snort daemon(s)"
	interfaces="$DEBIAN_SNORT_INTERFACE"
	# If we are requested to check for a specific interface...
	test "$2" && interfaces="$2"
        err=0
        pid=0
	for interface in $interfaces; do
                log_progress_msg " $interface "
                pidfile=/var/run/snort_$interface.pid
                if [ -f  "$pidfile" ] ; then
                        if [ -r "$pidfile" ] ; then
                            pidval=`cat $pidfile`
                            pid=$(expr "$pid" + 1)
                            if ps -p $pidval | grep -q snort; then
                                log_progress_msg "OK"
                            else
				log_progress_msg "ERROR"
				err=$(expr "$err" + 1)
			    fi
                         else
	       		     log_progress_msg "ERROR: cannot read status file"
                             err=$(expr "$err" + 1)
                         fi
                 else
                       log_progress_msg "ERROR"
                       err=$(expr "$err" + 1)
                 fi
        done
        if [ $err -ne 0 ] ; then
            if [ $pid -ne 0 ] ; then
# More than one case where pidfile exists but no snort daemon
# LSB demands a '1' exit value here
                log_end_msg  1
                exit 1
            else
# No pidfiles at all
# LSB demands a '3' exit value here
                log_end_msg  3
                exit 3
            fi
        fi
        log_end_msg  0
        ;;
  config-check)
        log_daemon_msg "Checking $DESC configuration" 
	if [ "$DEBIAN_SNORT_STARTUP" = "dialup" ]; then
		log_failure_msg "Config-check is currently not supported for snort in Dialup configuration"
                log_end_msg  3
                exit 3
	fi

	# usually, we test all interfaces
	interfaces="$DEBIAN_SNORT_INTERFACE"
	# if we are requested to test a specific interface...
	test "$2" && interfaces="$2"

	myret=0
	got_instance=0
	for interface in $interfaces; do
		got_instance=1
		log_progress_msg "interface $interface"

		CONFIGFILE=/etc/snort/snort.$interface.conf
		if [ ! -e "$CONFIGFILE" ]; then
			CONFIGFILE=/etc/snort/snort.conf
		fi
		COMMON=`echo $COMMON | sed -e 's/-D//'`
		set +e
                fail="INVALID"
		if [ -r "$CONFIGFILE" ]; then
                    $DAEMON -T $COMMON $DEBIAN_SNORT_OPTIONS \
			-c $CONFIGFILE \
			-S "HOME_NET=[$DEBIAN_SNORT_HOME_NET]" \
			-i $interface >/dev/null 2>&1
                    ret=$?
                else
                    fail="cannot read $CONFIGFILE"
                    ret=4
                fi
		set -e

		case "$ret" in
			0)
                                log_progress_msg "OK"
				;;
			*)
                                log_progress_msg "$fail"
				myret=$(expr "$myret" + 1)
				;;
		esac
	done
	if [ "$got_instance" = 0 ]; then
		log_failure_msg "no snort instance found to be started!" >&2
		exit 6
	fi

        if  [ $myret -eq 0 ] ; then
            log_end_msg 0
        else
            log_end_msg 1
        fi
	exit $myret
	;;
  *)
	echo "Usage: $0 {start|stop|restart|force-restart|reload|force-reload|status|config-check}"
	exit 1
	;;
esac
exit 0
