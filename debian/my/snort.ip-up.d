#!/bin/sh -e

test $DEBIAN_SCRIPT_DEBUG && set -v -x

# Initial configuration :)
DAEMON=/usr/sbin/snort
NAME=snort
DESC="Network Intrusion Detection System"

CONFIG=/etc/snort/snort.debian.conf
if [ -r /etc/snort/snort.common.parameters ] ; then
        COMMON=`cat /etc/snort/snort.common.parameters`
elif [ -r /etc/default/snort ] ; then
# Only read this if the old configuration is not present
        . /etc/default/snort
        COMMON="$PARAMS -l $LOGDIR -u $SNORTUSER -g $SNORTGROUP"
fi

test -x $DAEMON || exit 0
test -f $CONFIG && . $CONFIG
test "$DEBIAN_SNORT_STARTUP" = "dialup" || exit 0

# These are the cases in which this script can run:
# 1) with ppp environment set
# 1.1) from ppp/ip-up
# 1.2) from itself recursive
# 2) without ppp environment set
# 2.1) with saved ppp environment
# 2.1.1) with pppd running: saved ppp environment is valid
# 2.1.2) without pppd running: saved ppp environment is stale
# 2.2) without saved ppp environment
# 2.2.1) with pppd running
# 2.2.2) without pppd running
#
# Behaviour:
# 1.1, 1.2)
#	We just trust the environment, assume snort isn't already running,
#	overwrite any existing saved ppp environment with a new one
#	and leave it at that.
# 2.1.1)
#	We start snort with the values from the saved ppp environment.
# 2.1.2)
#	We remove the stale saved ppp environment and fall back to 2.2).
# 2.2.1)
#	We try to figure out the values that are correct and try
#	to start snort.
# 2.2.2)
# 	We warn and won't start.

check_log_dir() {
# Does the logging directory belong to Snort?
        # If we cannot determine the logdir return without error
        # (we will not check it)
        # This will only be used by people using /etc/default/snort
        [ -n "$LOGDIR" ] || return 0
        [ -n "$SNORTUSER" ] || return 0
        if [ ! -e "$LOGDIR" ] ; then
                echo -n "ERR: logging directory $LOGDIR does not exist"
                return 1
        elif [ ! -d "$LOGDIR" ] ; then
                echo -n "ERR: logging directory $LOGDIR does not exist"
                return 1
        else
                real_log_user=`stat -c %U $LOGDIR`
        # An alternative way is to check if the snort user can create
        # a file there...
                if [ "$real_log_user" != "$SNORTUSER" ] ; then
                        echo -n "ERR: logging directory $LOGDIR does not belong to the snort user $SNORTUSER"
                        return 1
                fi
        fi
        return 0
}

if ! check_log_dir; then
        echo "Cannot start $DESC!"
        exit 1
fi

if ! [ "$DEBIAN_SNORT_RECURSIVE" ]; then
	# Acquire lock...
	trap 'rm -f /var/run/snort.ppp.lock' 0
	for tries in $(seq 1 10); do
		mkfifo /var/run/snort.ppp.lock 2>/dev/null && break
		sleep 1
	done
	# Now it's locked or timed out.
	# In the latter case we assume stale lock.
fi

# If we are started with ppp environment set...
if [ "$PPPD_PID" -a "$PPP_IFACE" -a "$PPP_LOCAL" ]; then
	echo -n "Starting $DESC: $NAME($PPP_IFACE)"

	PIDFILE=/var/run/snort_$PPP_IFACE.pid
	ENVFILE=/var/run/snort_$PPP_IFACE.env

	fail="failed (check /var/log/daemon.log)"
	/sbin/start-stop-daemon --stop --signal 0 --quiet \
		--pidfile "$PIDFILE" --exec $DAEMON >/dev/null &&
			fail="already running"

	cd /etc/snort
	CONFIGFILE=/etc/snort/snort.$PPP_IFACE.conf
	if [ ! -e $CONFIGFILE ]; then
		echo "No /etc/snort/snort.$PPP_IFACE.conf, defaulting to snort.conf"
		CONFIGFILE=/etc/snort/snort.conf
	fi

	# We intentionally set +e here, thus (new) environment is even
	# saved, if startup fails - for further startup attempts
	set +e
	/sbin/start-stop-daemon --start --quiet --pidfile "$PIDFILE" \
		--exec $DAEMON -- $COMMON $DEBIAN_SNORT_OPTIONS \
		-c $CONFIGFILE \
		-S "HOME_NET=[$PPP_LOCAL/32]" \
		-i $PPP_IFACE >/dev/null
	ret=$?
	set -e
	case "$ret" in
		0)
			echo "."
			;;
		*)
			echo "...$fail."
			;;
	esac

	echo "PPPD_PID=$PPPD_PID"    > "$ENVFILE"
	echo "PPP_IFACE=$PPP_IFACE" >> "$ENVFILE"
	echo "PPP_LOCAL=$PPP_LOCAL" >> "$ENVFILE"

	exit $ret
fi

# Else, we are started without ppp environment set...

DEBIAN_SNORT_RECURSIVE=1
export DEBIAN_SNORT_RECURSIVE

# If we have saved environments, check and probably start them...
envpattern=/var/run/snort_*.env

# If we are requested to start one special environment...
test "$1" -a -z "$2" && envpattern=/var/run/snort_"$1".env

myret=0
got_instance=0
for env in $envpattern; do
	# This check is also needed, if the above pattern doesn't match
	test -f "$env" || continue;

	. "$env"

	# Prevent endless recursion because of damaged environments
	# Check, if the environment is still valid...
	if [ "$PPPD_PID" -a "$PPP_IFACE" -a "$PPP_LOCAL" ] &&
	   kill -0 $PPPD_PID 2>/dev/null &&
	   ps -p $PPPD_PID | grep -q pppd; then
		got_instance=1

		export PPPD_PID PPP_IFACE PPP_LOCAL
		# Because the starup of this particular environment could
		# fail, we guard it
		set +e
		$0 "$@"
		ret=$?
		set -e
		case "$ret" in
			0)
				;;
			*)
				myret=$(expr "$myret" + 1)
				;;
		esac
	else
		rm -f "$env"
	fi
done

# If we found no saved environments, we don't need to start anything
if [ "$got_instance" = 0 ]; then
	echo "No snort instance found to be started!" >&2
	exit 1
fi

exit $myret
