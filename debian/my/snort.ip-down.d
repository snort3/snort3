#!/bin/sh -e

test $DEBIAN_SCRIPT_DEBUG && set -v -x

# Initial configuration :)
DAEMON=/usr/sbin/snort
NAME=snort
DESC="Network Intrusion Detection System"

CONFIG=/etc/snort/snort.debian.conf

test -x $DAEMON || exit 0
test -f $CONFIG && . $CONFIG
test "$DEBIAN_SNORT_STARTUP" = "dialup" || exit 0

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
	echo -n "Stopping $DESC: $NAME($PPP_IFACE)"

	PIDFILE=/var/run/snort_$PPP_IFACE.pid
	ENVFILE=/var/run/snort_$PPP_IFACE.env

	test -f "$PIDFILE" && pid=$(cat "$PIDFILE")

	# We remove the saved environment, if we are not asked to
	# keep them. DEBIAN_SNORT_KEEPENV is not set, if we're
	# called by pppd, thus we always remove stale environments.
	test $DEBIAN_SNORT_KEEPENV || rm -f "$ENVFILE"

	/sbin/start-stop-daemon --stop --retry 5 --quiet --oknodo \
		--pidfile "$PIDFILE" --exec $DAEMON >/dev/null
	rm -f "$PIDFILE"

	echo "."

	exit 0
fi

# Else, we are started without ppp environment set...

DEBIAN_SNORT_RECURSIVE=1
export DEBIAN_SNORT_RECURSIVE

# We keep the environments, thus the instances are restartable
DEBIAN_SNORT_KEEPENV=1
export DEBIAN_SNORT_KEEPENV

# If we have saved environments, check and probably stop them...
envpattern=/var/run/snort_*.env

# If we are requested to stop one special environment...
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
		# Because the stop of this particular environment could
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

# If we found no saved environments, we don't need to stop anything
if [ "$got_instance" = 0 ]; then
	echo "No snort instance found to be stopped!" >&2
fi

exit $myret
