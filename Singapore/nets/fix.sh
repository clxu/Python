#!/bin/bash

#########################################################
#							#
#	Date  2014/06   for Nets  Hardening	Fix	#
# if you wan't used Section 7.2 disable account user /bin/bash to /sbin/nologin
# Pls remove "#"																				#
#########################################################
mkdir /tmp/OS_CHECK
osdir="/tmp/OS_CHECK"

#Section 1.1.1 - 1.1.4 Partition of /tmp and options' Pls Manual Check ,

#Section 1.1.5 Partition of /var and options' options' Pls Manual Check ,

#Section 1.1.6 Bind Mount the /var/tmp directory to /tmp'options' Pls Manual Check ,

#Section 1.1.7 Partition of /var/log and options'Pls Manual Check,

#Section 1.1.8 Partition of /var/log/audit and options'Pls Manual Check,

#Section 1.1.9 - 1.1.10 Partition of /home and options'Pls Manual Check, 

#Section 1.1.14 - 1.1.16 Partition of /dev/shm and options'Pls Manual Check,

#Section 1.1.17 Set Sticky Bit on All World-Writable Directories'Pls Manual Check,

#Section 1.2.2 Verify Red Hat GPG key is Installed'Pls Manual Check , 

#Section 1.2.3 Verify that gpgcheck is Globally Activated',
mkdir $osdir/1.2.3
cp /etc/yum.conf $osdir/1.2.3/
sed -i 's/gpgcheck=0/gpgcheck=1/g' /etc/yum.conf

#Section 3.6 Configure Network Time Protocol',

#Section 3.6 Check /etc/sysconfig/ntpd',

#Section 3.16 Configure Mail Transfer Agent for Local-Only Mode',

#Section 6.1.2 Enable Cron Daemon',
chkconfig crond on;service crond start

#Section 6.2.12 Set Idle Timeout Interval for User Login',
mkdir $osdir/6.2.12
cp /etc/ssh/sshd_config $osdir/6.2.12
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 0/g' /etc/ssh/sshd_config

#Section 6.2.14 Set SSH Banner',
sed -i 's/#Banner none/Banner \/etc\/issue.net/g' /etc/ssh/sshd_config

#Section 6.3.1 Upgrade Password Hashing Algotithm SHA-512',

#Section 6.3.6 Limit Password Reuse',
mkdir $osdir/6.3.6
cp /etc/pam.d/system-auth  $osdir/6.3.6/
sed -i 's/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5/g' /etc/pam.d/system-auth

#Section 8.1 Set Warning Banner for Standard Login Services /etc/motd',
mkdir $osdir/8.1
cp /etc/motd $osdir/8.1/
chmod 644 /etc/motd

#Section 8.1 Set Warning Banner for Standard Login Services /etc/issue',
cp /etc/issue $osdir/8.1/
chmod 644 /etc/issue

#Section 8.1 Set Warning Banner for Standard Login Services /etc/issue.net',
cp /etc/issue.net $osdir/8.1/
chmod 644 /etc/issue.net

#Section 8.2 Remove OS Information from Login Warning Banners',
echo "Authorized uses only. All activity may be monitored and reported" > /etc/issue
echo "Authorized uses only. All activity may be monitored and reported" > /etc/issue.net

#Section 8.2 /etc/motd Remove OS Information from Login Warning Banners',

#Section 9.1.10 Find World Writable Files',

#Section 9.1.11 Find Un-owned Files and Directories',
mkdir $osdir/9.1.11
df --local -P | awk {'if(NR!=1)print $6'}|xargs -I '{}' find '{}' -xdev -nouser -ls > /$osdir/9.1.11/nouser.txt
for i in `cat $osdir/9.1.11/nouser.txt`; do chown root $i;done


#Section 9.1.12 Find Un-grouped Files and Directories',
mkdir $osdir/9.1.12
df --local -P | awk {'if(NR!=1)print $6'}|xargs -I '{}' find '{}' -xdev -nogroup -ls > /$osdir/9.1.12/nogroup.txt
for i in `cat $osdir/9.1.11/nogroup.txt`; do chown root $i;done

#Section 9.2.5 Verify No UID 0 Accounts Exist Other Than root',

#Section 9.2.20 Check for Presence of User .netrc Files',
mkdir $osdir/9.2.5
find / -name .netrc -exec mv {} $osdir/9.2.5 \;

#Section 9.2.21 Check for Presence of User .forward Files',
mkdir $osdir/9.2.6
find / -name .forward -exec mv {} $osdir/9.2.6 \;

echo "=================================================================="

#Section 2.1.1 Remeove telnet-server',

#Section 2.1.3 Remove rsh-server' , 

#Section 2.1.4 Remove rsh',

#Section 2.1.6 Remove NIS Server',

#Section 2.1.7 Remove tftp',

#Section 2.1.8 Remove tftp-server',

#Section 2.1.9 Remove talk',

#Section 2.1.10 Remove talk-server',
for i in {telnet-server,rsh-server,rsh,ypserv,tftp,tftp-server,talk,talk-server,dhcp};
do
	yum -y remove $i;
done

#Section 3.2 Remove X Windows',
mkdir $osdir/3.2
cp /etc/inittab $osdir/3.2
sed -i 's/id:5:/id:3:/g' /etc/inittab

#Section 3.1 Set Daemon umask',
mkdir $osdir/3.1
cp /etc/sysconfig/init $osdir/3.1/
echo "umask 027" >> /etc/sysconfig/init

#Section 3.5 Remove DHCP Server,',

#Section 2.1.12 Disable chargen-dgram',
#Section 2.1.13 disable chargen-stream',
#Section 2.1.14 Disable daytime-dgran',
#Section 2.1.15 Disable daytime-stream',
#Section 2.1.16 Disable echo-dgram',
#Section 2.1.17 Disable echo-stream',
#Section 2.1.18 Disable tcpmux-server',
for x in {chargen-dgram,chargen-stream,daytime-stream,echo-dgram,echo-stream,tcpmux-server,avahi-daemon};
do
	chkconfig $x off;
done

#Section 3.3 Disable Avahi Server',


echo "=================================================================="

#Section 4.1.1 Disable IP Forwarding',
mkdir $osdir/sysctl
cp -ap /etc/sysctl.conf $osdir/sysctl/
sed -i 's/net.ipv4.ip_forward = 1/net.ipv4.ip_forward = 0/g' /etc/sysctl.conf

#Section 4.1.2 Disable Send Packet Redirects',
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf

#Section 4.2.1 Disable Source Routed Packet Acceptance',
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf

#Section 4.2.2 Disable ICMP Redirect Acceptance',
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf

#Section 4.2.3 Disable Secure ICMP redirect Acceptance',
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf

#Section 4.2.4 Log Suspicious Packets',
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf

#Section 4.2.5 Enable Ignore Broadcast Requests',
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf


#Section 4.2.6 Enable Bad Error Message Protection',
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf

#Section 4.2.7 Enable RFS-recommended Source Route Validation',
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf

#Section 4.2.8 Enable TCP SYN Cookies',
sed -i 's/net.ipv4.tcp_syncookies = 0/net.ipv4.tcp_syncookies = 1/g' /etc/sysctl.conf
sysctl -p

#Section 4.5.3 Verify Permissions on /etc/hosts.allow',
mkdir $osdir/4.5.3
cp /etc/hosts.allow $osdir/4.5.3
chmod 644 /etc/hosts.allow

#Section 4.5.5 Verify Permissions on /etc/hosts.deny',
mkdir $osdir/4.5.5
cp /etc/hosts.deny $osdir/4.5.5
chmod 644 /etc/hosts.deny

#Section 4.7 Enable IPtables',
chkconfig iptables on
service iptables start

#Section 6.2.1 Set SSH protocol to 2  or 3',

#Section 6.2.4 Disable SSH X11 Forwarding',
sed -i 's/#X11Forwarding no/X11Forwarding no/g' /etc/ssh/sshd_config

#Section 6.2.5 - 6.2.7 Set SSH MAXauth tries to 3 and IgnoreRhosts to Yes and HostbasedAuthentication to No',
sed -i 's/#IgnoreRhosts yes/IgnoreRhosts yes/g' /etc/ssh/sshd_config
sed -i 's/#HostbasedAuthentication no/HostbasedAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/g' /etc/ssh/sshd_config

#Section 6.2.8 Disable SSH Root Login',
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config

#Section 6.2.9 Set SSH PermitEmptyPasswords to No',
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config

#Section 6.2.10 Do not Allow Users to Set Environment Options',
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/g' /etc/ssh/sshd_config

#'Use Only Approved Cipher in Counter Mode',

#Section 5.1.1 Install the rsyslog packages',
#Section 5.1.2 Activate the rsyslog Service',
chkconfig rsyslog on

#Section 5.1.5 Configure rsyslog to Send Logs to TLC',
mkdir $osdir/5.1.5 
cp /etc/rsyslog.conf $osdir/5.1.5/
sed -i 's/\/var\/log\/secure/@tlc/g' /etc/rsyslog.conf
service rsyslog restart

#Section 5.1.6 Configure hosts file to contain tlc IP address',
# echo "172.18.34.165   tlc" >> /etc/hosts

#Section 6.2.2 Set LogLevel to INFO',
sed -i 's/#LogLevel INFO/LogLevel INFO/g' /etc/ssh/sshd_config

echo "=================================================================="

#Section 1.5.1 Set User/Group Owner on /etc/grub.conf',
mkdir $osdir/1.5.1
cp -ap /boot/grub/grub.conf  $osdir/1.5.1
chown root.root /boot/grub/grub.conf

#Section 6.1.4 - 6.1.9 Set User/Group Owner and permission on  /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d',
mkdir $osdir/6.1.4
cp -rf /etc/crontab /etc/cron.d/   $osdir/6.1.4

chmod 644 /etc/crontab
chmod 755 /etc/cron.hourly
chmod 755 /etc/cron.daily
chmod 755 /etc/cron.weekly
chmod 755 /etc/cron.monthly 
chmod 755 /etc/cron.d

#Section 1.5.2 Set Permissions on /etc/grub.conf',
chmod 600 /boot/grub/grub.conf

#Section 6.2.3 Set permissions on /etc/ssh/sshd_config',
chmod 600 /etc/ssh/sshd_config

#Section 9.1.2 , 9.1.6 Verify Permissions and Ownership on /etc/passwd ',
mkdir $osdir/9.1.2
cp -ap /etc/passwd $osdir/9.1.2
chmod 644 /etc/passwd ; chown root.root /etc/passwd

#Section 9.1.5 , 9.1.9 Verify Permissions and Ownership on /etc/group',
mkdir $osdir/9.1.5
cp -ap /etc/group $osdir/9.1.5
chmod 644 /etc/group ; chown root.root /etc/group

#Section 9.1.3 , 9.1.7 Verify Permissions and Ownership on /etc/shadow',
mkdir $osdir/9.1.3
cp -ap /etc/shadow $osdir/9.1.3
chmod 000 /etc/shadow ; chown root.root /etc/shadow
 
#Section 9.1.4 , 9.1.8 Verify Permissions and Ownership on /etc/gshadow ',
mkdir $osdir/9.1.4
cp -ap /etc/gshadow $osdir/9.1.4
chmod 000 /etc/gshadow ; chown root.root /etc/gshadow

#Section 7.1.1 - 7.1.3 Set Password Expireation  Change Expiring Warning Days Change Minmum Number of Days',
mkdir $osdir/7.1.1
cp -ap /etc/login.defs $osdir/7.1.1/
sed -i '/PASS_MAX_DAYS/d' /etc/login.defs
echo "PASS_MAX_DAYS	90" >> /etc/login.defs
sed -i '/PASS_MIN_DAYS/d' /etc/login.defs
echo " PASS_MIN_DAYS   7" >> /etc/login.defs

#Section 7.2 Disable System Accounts',
#mkdir $osdir/7.2
#cp /etc/passwd $osdir/7.2/
#egrep -v "^\+" /etc/passwd |awk -F : '($1 != "root" && $1 !="sync" && $1 != "shutdown" && $1 !="halt" && $3 < 500 && $7 != "/sbin/nologin"){print}' > $osdir/7.2/disableuser
#for i in `cat $osdir/7.2/disableuser`;
#do
#usermod -s /sbin/nologin  $i;
#done


#Section 7.3 Set Default Group for root Account',

#Section 7.4 set Default Umask for Users',
mkdir $osdir/7.4
cp -ap /etc/bashrc /etc/profile $osdir/7.4
echo "umask=077" >> /etc/bashrc
echo "umask=077" >> /etc/profile

#Section 7.5 Lock Inactive User Accounts',

#Section 9.2.1 Ensure Password Fields are Not Empty',

#Section 9.2.2 - 9.2.4 Verify No Legacy "+" Entries Exist in /etc/passwd /etc/shadow /etc/group File'


echo "The End"





