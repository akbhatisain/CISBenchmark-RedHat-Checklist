#!/bin/bash

hostN=$( hostname -s )
hasSudo=1
Release="Unknown"
[ -n "$( grep 'release 5' /etc/redhat-release )" ] && Release=RH5
[ -n "$( grep 'release 6' /etc/redhat-release )" ] && Release=RH6
[ -n "$( grep 'release 7' /etc/redhat-release )" ] && Release=RH7
[ -n "$( grep 'release 8' /etc/redhat-release )" ] && Release=RH8
[ "Release" == "RH8" ] && pkgMgr=dnf || pkgMgr=yum
PKGS=$( rpm -qa --qf "\:%{NAME}\:\n" )

if [ `whoami` == 'root' ]
then
  Sudo=""
else
  Sudo="sudo"
fi

BootLoaderPasswordTest () {
  Msg=$( grep "^set superusers " /boot/grub2/grub.cfg )
  [ -n "$Msg" ] || echo "set superusers missing"

  Msg=$( grep "^password_pbkdf2 " /boot/grub2/grub.cfg )
  [ -n "$Msg" ] || echo "password is missing"
}

BootLoaderPassword () {
  guidance=$1

  if [ "$hasSudo" != "1" ]
  then
    echo "$guidance,$Release,$hostN,BootLoaderPassword no sudo access,Exception"
    return 1
  fi

  if [ -e /boot/grub/grub.conf ]
  then
    Grub='/boot/grub/grub.conf'
  else
    Msg=$( BootLoaderPasswordTest )
    if [ -n "$Msg" ]
    then
      echo "$guidance,$Release,$hostN,BootLoaderPasswordTest failed,Noncompliant"
    else
      echo "$guidance,$Release,$hostN,BootLoaderPassword OK,Compliant"
    fi
    return 1
  fi

  Msg="`$Sudo grep ^password[[:space:]] $Grub`"
  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,BootLoaderPassword found,Compliant"
  else
    echo "$guidance,$Release,$hostN,BootLoaderPassword not found,Noncompliant"
  fi
}

CheckCron () {
  guidance=$1

  if [ -z "`echo $PKGS | grep -o '\:cronie\:'`" ]
  then
    echo "$guidance,$Release,$hostN,cronie not installed,Compliant"
    return 1
  fi

  CheckPermissions1 $guidance "/etc/crontab" "644 root root"
}

CheckEnabled () {
  guidance=$1
  serv="$2" 
  fail=${3:-"Noncompliant"}

  if [ -z "$( which systemctl 2> /dev/null )" ]
  then
    Msg="$( chkconfig --list | grep $serv | grep -w on )"
  else
    Msg="$( systemctl is-enabled $serv | grep -i '^enabled' )"
  fi

  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,CheckEnabled $serv,Compliant"
  else
    echo "$guidance,$Release,$hostN,CheckEnabled $serv not enabled,$fail"
  fi 
}

CheckGDM () {
  guidance=$1

  if [ -z "`echo $PKGS | grep -o '\:gdm\:'`" ]
  then
    echo "$guidance,$Release,$hostN,gdm package not installed,Compliant"
  else
    echo "$guidance,$Release,$hostN,gdm package installed,Noncompliant"
  fi
}

CheckGroups () {
  guidance=$1

  tmpfile1=$(mktemp /tmp/RHC1.XXXXXX) || exit
  awk -F: '{print $4}' /etc/passwd | sort -u > $tmpfile1

  tmpfile2=$(mktemp /tmp/RHC2.XXXXXX) || exit
  awk -F: '{print $3}' /etc/group | sort -u > $tmpfile2

  Msg=$(comm -23 $tmpfile1 $tmpfile2)

  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,CheckGroups some groups in /etc/passwd not found in /etc/groups,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,CheckGroups all groups in /etc/passwd are found in /etc/groups,Compliant"
  fi

  [ -n "$tmpfile1" ] && rm $tmpfile1
  [ -n "$tmpfile2" ] && rm $tmpfile2
}

CheckIP6Ads () {
  guidance=$1

  if [ "$Release" == "RH8" ]
  then
    if [ -n "$( sysctl net.ipv6.conf.all.accept_ra | grep '^net.ipv6.conf.all.accept_ra = 0$' )" ]
    then
      if [ -n "$( sysctl net.ipv6.conf.default.accept_ra | grep '^net.ipv6.conf.default.accept_ra = 0$' )" ]
      then
        echo "$guidance,$Release,$hostN,CheckIP6Ads,Compliant"
      else
        echo "$guidance,$Release,$hostN,net.ipv6.conf.default.accept_ra missing,Exception"
      fi
    else
      echo "$guidance,$Release,$hostN,net.ipv6.conf.all.accept_ra missing,Exception"
    fi
  else
    echo "$guidance,$Release,$hostN,$Release NA === RH7?,Compliant"
  fi
}

CheckLogPermissionsTest () {
  find /var/log -type f -exec stat -c "0%a %n" {} \; 2>/dev/null | while read permissions fname X
  do
    if [ $(( $permissions & 037 )) -ne 0 ]
    then
      ( echo "$fname" | grep '^/var/log/up2date' > /dev/null ) && continue
      ( echo "$fname" | grep '^/var/log/elx-install.log' > /dev/null ) && continue
      ( echo "$fname" | grep '^/var/log/iu-install.log' > /dev/null ) && continue
      ( echo "$fname" | grep '^/var/log/prelink/prelink.log' > /dev/null ) && continue
      ( echo "$fname" | grep '^/var/log/boot.log' > /dev/null ) && continue
      ( echo "$fname" | grep '^/var/log/lastlog' > /dev/null ) && continue
      ( echo "$fname" | grep '^/var/log/sa/sa' > /dev/null ) && continue
      ( echo "$fname" | grep '^/var/log/ConsoleKit/history' > /dev/null ) && continue
      ( echo "$fname" | grep '^/var/log/yum.txt' > /dev/null ) && continue
      ( echo "$fname" | grep '^/var/log/wtmp' > /dev/null ) && continue
      ( echo "$fname" | grep '^/var/log/dmesg' > /dev/null ) && continue
      ( echo "$fname" | grep '^/var/log/rhsm/' > /dev/null ) && continue
      ( echo "$fname" | grep '^/var/log/mcelog' > /dev/null ) && continue
      ( echo "$fname" | grep '^/var/log/cbsensor/' > /dev/null ) && continue
      ( echo "$fname" | grep '^/var/log/rear/' > /dev/null ) && continue
      ( echo "$fname" | grep '^/var/log/cb/integrations/' > /dev/null ) && continue
      ls -l $fname
    fi
  done
}

CheckLogPermissions () {
  guidance=$1

  Msg=$( CheckLogPermissionsTest | head -n1 )

  if [ -n "$Msg" ]
  then
    echo "$Msg"
    echo "$guidance,$Release,$hostN,CheckLogPermissions failed,Exception"
  else
    echo "$guidance,$Release,$hostN,CheckLogPermissionsTest OK,Compliant"
  fi
}

CheckLogrotate () {
  guidance=$1

  if [ -e /etc/logrotate.conf ]
  then 
    echo "$guidance,$Release,$hostN,CheckLogrotate need more info ??,Compliant"
  else
    echo "$guidance,$Release,$hostN,CheckLogrotate need more info ??,Noncompliant"
  fi
}

CheckLogsToRemoteTest () {
  grep "^*.*[^I][^I]*@" /etc/rsyslog.conf
}

CheckLogsToRemote () {
  guidance=$1

  Msg=$( CheckLogsToRemoteTest | head -n1 )

  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,CheckLogsToRemoteTest OK,Compliant"
  else
    echo "$guidance,$Release,$hostN,CheckLogsToRemoteTest failed,Noncompliant"
  fi
}

CheckNTP () {
  guidance=$1

  if [ -n "$( grep '^restrict -4 default kod nomodify notrap nopeer noquery$' /etc/ntp.conf )" ]
  then
    if [ -n "$( grep '^restrict -6 default kod nomodify notrap nopeer noquery$' /etc/ntp.conf )" ]
    then
      if -n "$( grep '^Options=' /etc/sysconfig/ntpd | grep '\-u ntp:ntp' )" ]
      then
        echo "$guidance,$Release,$hostN,CheckNTP OK,Compliant"
      else
        echo "$guidance,$Release,$hostN,-u ntp:ntp missing,Noncompliant"
      fi
    else
      echo "$guidance,$Release,$hostN,ntp restrict -6 missing,Noncompliant"
    fi
  else
    echo "$guidance,$Release,$hostN,ntp restrict -4 missing,Noncompliant"
  fi
}

CheckPasswordReqTest () {

if [ ! -e /etc/security/pwquality.conf ]
then
  echo "/etc/security/pwquality.conf missing"
  return 1
fi

if [ ! -e /etc/pam.d/password-auth ]
then
  echo "/etc/pam.d/password-auth missing"
  return 1
fi

grep pam_pwquality.so /etc/pam.d/password-auth 
# password requisite pam_pwquality.so try_first_pass retry=3 

grep pam_pwquality.so /etc/pam.d/system-auth 
# password requisite pam_pwquality.so try_first_pass retry=3

grep ^minlen /etc/security/pwquality.conf 
#minlen=14

grep ^dcredit /etc/security/pwquality.conf 
# dcredit=-1 

grep ^lcredit /etc/security/pwquality.conf 
#lcredit=-1 

grep ^ocredit /etc/security/pwquality.conf 
#ocredit=-1 

grep ^ucredit /etc/security/pwquality.conf
#ucredit=-1
}

CheckPasswordReq () {
  guidance=$1

  if [ -z "" ]
  then
    echo "$guidance,$Release,$hostN,CheckPasswordReqTest CyberArk,Compliant"
    return 1
  fi

  Msg=$( CheckPasswordReqTest )

  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,CheckPasswordReqTest failed ===,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,CheckPasswordReqTest OK ===,Compliant"
  fi
}

CheckPermissions1 () {
  guidance=$1
  fileName=$2
  permissions="$3"

  s=$( stat -c '%a %U %G' $fileName )
  p=$( echo $s | grep "$permissions" )
  if [ "$p" == "$permissions" ]
  then
    echo "$guidance,$Release,$hostN,$fileName $p,Compliant"
  else
    echo "$guidance,$Release,$hostN,$fileName $s,Noncompliant"
  fi
}

CheckPermissions2 () {
  guidance=$1
  fileName=$2
  notPermissions=$(( 0$3 ))

  s=$( stat -c '%a %U %G' $fileName )
  if [ -z "$( echo $s | grep 'root root' ) ] && [ -z "$( echo $s | grep 'root shadow' ) ]
  then
    echo "$guidance,$Release,$hostN,$fileName $s wrong group or owner,Noncompliant"
    return 1
  fi

  perm10=$(( 0$( echo $s | cut -d' ' -f1 ) )) 
  if [ $(( $perm10 & $notPermissions )) -eq 0 ]
  then
    echo "$guidance,$Release,$hostN,$fileName $s OK,Compliant"
  else
    echo "$guidance,$Release,$hostN,$fileName $s wrong permissions,Noncompliant"
  fi
}

CheckPermissions () {
  guidance=$1
  fileName=$2
  permissions="$3"

  Msg=`stat -c "%a %n" "$fileName" | grep "$permissions"`
  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,$Msg,Compliant"
  else
    echo "$guidance,$Release,$hostN,CheckPermissions $fileName $permissions,Noncompliant"
  fi
}

CheckRSysLogTest () {
   find /var/log -mtime -1 -ls 2>/dev/null
}

CheckRSysLog () {
  guidance=$1

  Msg=$( CheckRSysLogTest | head -n1 )

  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,CheckRSysLogTest OK,Compliant"
  else
    echo "$guidance,$Release,$hostN,CheckRSysLogTest failed,Noncompliant"
  fi
}

CheckSSHPermissions () {
  guidance=$1
  permissions="$2"

  Fils="$( find /etc/ssh -xdev -type f -name 'ssh_host_*_key')"
  for fn in $Fils
  do
    Msg="$( stat -c '%n %a %U %G' $fn )"
    if [[ ! "$Msg" =~ "$permissions" ]]
    then
      echo "$guidance,$Release,$hostN,$Msg,Noncompliant"
      return 1
    fi
  done

  echo "$guidance,$Release,$hostN,CheckSSHPermissions $Msg,Compliant"
}

CheckSSHPrivatePermissionsTest () {
  guidance=$1
  permissions="$2"

  Fils="$( find /etc/ssh -xdev -type f -name 'ssh_host_*_key' )"
  for fn in $Fils
  do
    Msg="$( $Sudo stat -c '%n %a %U %G' $fn )"
    Perm=$( echo $Msg | cut -d' ' -f2 )
    User=$( echo $Msg | cut -d' ' -f3 )
    Group=$( echo $Msg | cut -d' ' -f4 )

    if [ "$User" != "root" ]
    then
      echo "$Msg : user is not root"
    fi

    if [ "$Release" == "RH8" ]
    then
      if [ "$Group" != "root" ]
      then
        echo "$Msg : group is not root"
      fi

      if [ "$Perm" != "600" ]
      then
        echo "$Msg : permissions are not 600"
      fi
    else
      if [ "$Group" != "ssh_keys" ] && [ "$Group" != "root" ]
      then
        echo "$Msg : group is not root or ssh_keys"
      fi

      perm10=$(( 0$Perm & 0137 ))
      if [ $perm10 -ne 0 ]
      then
        echo "$Msg : permissions are invalid"
      fi
    fi
  done
}

CheckSSHPrivatePermissions () {
  guidance=$1

  if [ "$hasSudo" != "1" ]
  then
    echo "$guidance,$Release,$hostN,CheckSSHPrivatePermissions no sudo access,Exception"
    return 1
  fi

  Msg="$( CheckSSHPrivatePermissionsTest | head -n1 )"

  if [ -n "$Msg" ]
  then
     echo "$guidance,$Release,$hostN,CheckSSHPrivatePermissionsTest failed,Noncompliant"
  else
     echo "$guidance,$Release,$hostN,CheckSSHPrivatePermissionsTest OK,Compliant"
  fi
}

CheckSSHPublicPermissions () {
  guidance=$1
  permissions="$2"

  Fils="$( find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub')"
  for fn in $Fils
  do
    Msg="$( stat -c '%n %a %U %G' $fn )"
    if [[ ! "$Msg" =~ "$permissions" ]]
    then
      echo "$guidance,$Release,$hostN,$Msg,Noncompliant"
      return 1
    fi
  done

  echo "$guidance,$Release,$hostN,CheckSSHPermissions $Msg,Compliant"
}

CheckTimeSync () {
  guidance=$1

  if [ -n "`echo $PKGS | grep -o '\:ntp\:\|\:chrony\:'`" ]
  then
    echo "$guidance,$Release,$hostN,ntp/chrony installed,Compliant"
  else
    echo "$guidance,$Release,$hostN,ntp/chrony not installed,Noncompliant"
  fi
}

CheckUpdates () {
  guidance=$1

  if [ -z "" ]
  then
    echo "$guidance,$Release,$hostN,Patches are applied every 30 days by Security Mandate,Compliant"
    return 1
  fi

  grepIgnore='^Loaded\|^Limiting\|^No packages needed\|^              : '

# without --security is faster, so do it first
  Msg=$( ${pkgMgr} check-update 2>/dev/null | grep -v "$grepIgnore" )
  if [ -z "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,check-update packages OK,Compliant"
    return 1
  fi

  Msg=$( ${pkgMgr} --security check-update 2>/dev/null | grep '^Limiting' -A20 | grep -v "$grepIgnore" )
  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,Security packages need to be installed,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,Security packages OK,Compliant"
  fi
}

DefaultUmaskTest () {
  [ "$Release" == "RH8" ] && return 1

  Msg=$( grep -w 'umask' /etc/profile.d/*.sh /etc/profile /etc/bashrc | grep -v "\#" )
  if [ $( echo "$Msg" | wc -l ) -ne 1 ]
  then
    echo "Multiple umasks found"
    return 1
  fi

  echo $Msg | grep -v "umask 027"
}

DefaultUmask () {
  guidance=$1

  Msg=$( DefaultUmaskTest )

  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,DefaultUmaskTest $Msg,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,DefaultUmaskTest OK,Compliant"
  fi
}

EmptyShadowGroup () {
  guidance=$1

  Msg=$( awk -F: '($1 == "shadow") {print $4}' /etc/group )
  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,EmptyShadowGroup users in shadow group,Noncompliant"
    return 1
  fi

  Msg=$( awk -F: '($4 == "<shadow-gid>") {print}' /etc/passwd )
  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,EmptyShadowGroup shadow-gid found in /etc/passwd,Noncompliant"
    return 1
  fi

#  shadowGroup=`awk '/^wheel:/ {print $0}' /etc/group | tr ':' ' ' | awk '{print $3}'`
#  if [ -z "$shadowGroup" ]
#  then
#    echo "$guidance,$Release,$hostN,EmptyShadowGroup no shadow group,Compliant"
#   return 1
#  fi

  echo "$guidance,$Release,$hostN,EmptyShadowGroup,Compliant"
}

GPGCheckTest ()
{
  grep '^\s*gpgcheck\s*=\s*[0,2-9,A-Z,a-z]' /etc/yum.conf /etc/yum.repos.d/*.repo
}

GPGCheck ()
{
  guidance=$1

  Msg=$( GPGCheckTest | head -n1 )
  if [ -z "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,GPGCheckTest OK,Compliant"
  else
    echo "$guidance,$Release,$hostN,GPGCheckTest failed,Noncompliant"
  fi
}

GPGKeyConfigured () {
  guidance=$1

  Msg=$( rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n' )

  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,GPGKeyConfigured OK ===,Compliant"
  else
    echo "$guidance,$Release,$hostN,GPGKeyConfigured - what is site policy? ===,Noncompliant"
  fi
}

IP6 () {
  guidance=$1

  if [ $hasSudo -ne 1 ]
  then
    echo "$guidance,$Release,$hostN,IP6 requires root,Exception"
    return 1
  fi

  echo "$guidance,$Release,$hostN,IP6DefaultDeny need to fix,Exception"

  if [ -n "$( $Sudo ip6tables --list-rules | grep '$2' )" ]
  then
    if [ -n "$3" ]
    then
      IP6DefaultDeny $1 "$3" "$4" "$5" "$6" "$7" "$8"
    else
      echo "$guidance,$Release,$hostN,IP6DefaultDeny OK,Compliant"
    fi
  else
    echo "$guidance,$Release,$hostN,IP6DefaultDeny missing '$2',Exception"
  fi
}

IP6CheckFileTest () {
   ls -l /etc/sysconfig/ip6tables >/dev/null 2>/dev/null || echo "/etc/sysconfig/ip6tables not found"
}

IP6CheckFile () {
  guidance=$1

  if [ "$Release" == "RH8" ]
  then
    echo "$guidance,$Release,$hostN,IP6CheckFile RedHat 8 NA,Compliant"
    return 1
  fi

  Msg=$( IP6CheckFileTest )
  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,IP6CheckFileTest $Msg,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,IP6CheckFileTest OK ===,Exception"
  fi
}

IP6DefaultDenyTest () {
  mode=$1

  Msg=$( $Sudo ip6tables --list | tr '\(' ' ' | tr '\)' ' ' | grep "Chain $mode  policy " )
  if [ -z "$Msg" ]
  then
    echo "Chain $mode policy missing"
    return 1
  fi

  if [ -z $( echo $Msg | awk '{if ($4=="DROP" || $4=="DENY") print}' ) ]
  then
    echo $Msg
    return 1
  fi
}

IP6DefaultDeny () {
  guidance=$1

  if [ $hasSudo -ne 1 ]
  then
    echo "$guidance,$Release,$hostN,IP6DefaultDeny requires root,Exception"
    return 1
  fi

  Msg=$( IP6DefaultDenyTest "INPUT" | head -n1 )
  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,IP6DefaultDenyTest $Msg,Exception"
    return 1
  fi

  Msg=$( IP6DefaultDenyTest "OUTPUT" | head -n1 )
  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,IP6DefaultDenyTest $Msg,Exception"
    return 1
  fi

  Msg=$( IP6DefaultDenyTest "FORWARD" | head -n1 )
  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,IP6DefaultDenyTest $Msg,Exception"
    return 1
  fi

  echo "$guidance,$Release,$hostN,IP6DefaultDenyTest OK,Compliant"
}

IP6LoopbackTest () {

  Msg=$( $Sudo ip6tables -L INPUT -v -n )

  if [ -z "$( echo $Msg | grep '0 0 ACCEPT all -- lo * 0.0.0.0/0 0.0.0.0/0' )" ]
  then
    echo "Input ACCEPT all -- lo missing"
    return 1
  fi

  if [ -z "$( echo $Msg | grep '0 0 DROP all -- * * 127.0.0.0/8 0.0.0.0/0' )" ]
  then
    echo "Input DROP all missing"
    return 1
  fi

  Msg=$( ip6tables -L OUTPUT -v -n )

  if [ -z "$( echo $Msg | grep '0 0 ACCEPT all -- * lo 0.0.0.0/0 0.0.0.0/0' )" ]
  then
    echo "Output ACCEPT all missing"
    return 1
  fi
}

IP6Loopback () {
  guidance=$1

  if [ $hasSudo -ne 1 ]
  then
    echo "$guidance,$Release,$hostN,IP6DefaultDeny requires root,Exception"
    return 1
  fi

  Msg=$( IP6LoopbackTest | head -n1 )

  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,IP6LoopbackTest $Msg,Exception"
    return 1
  fi

  echo "$guidance,$Release,$hostN,IP6LoopbackTest OK,Exception"
}

IP6OpenPortsTest () {
  
  Msg=$( netstat --listening --numeric --protocol inet6 | grep -v "^Active\|^Proto" | awk '{print $4}' | awk -F: '{print $NF}' | sort -u )
  [ -z "$Msg" ] && return 1

  tmpfile1=$(mktemp /tmp/RHC1.XXXXXX) || exit
  echo "$Msg" > $tmpfile1

  Msg=$( $Sudo ip6tables --list --numeric | grep -o 'dpt:[1-9].*$' | awk -F: '{print $2}' | sort -u )
  if [ -z "$Msg" ]
  then
    echo "No firewall rules for IP6"
    rm $tmpfile1
    return 1
  fi

  tmpfile2=$(mktemp /tmp/RHC2.XXXXXX) || exit
  echo "$Msg" > $tmpfile2

  Msg=$( comm -23 $tmpfile1 $tmpfile2 )
  rm $tmpfile1 $tmpfile2

  [ -n "$Msg" ] && echo $Msg
}

IP6OpenPorts () {
  guidance=$1

  if [ $hasSudo -ne 1 ]
  then
    echo "$guidance,$Release,$hostN,IP6DefaultDeny requires root,Exception"
    return 1
  fi

  Msg=$( IP6OpenPortsTest | head -n1 )
  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,IP6OpenPorts $Msg,Exception"
  else
    echo "$guidance,$Release,$hostN,IP6OpenPorts OK,Compliant"
  fi
}

LocalLoginWarningBanner () {
  guidance=$1

### see if empty

  if [ ! -e /etc/motd ]
  then
    echo "$guidance,$Release,$hostN,/etc/motd not found,Compliant"
  else
    if [ -n "$( grep -i '[^[:print:]]\|os version' /etc/motd )" ]
    then
      echo "$guidance,$Release,$hostN,/etc/motd contains special characters,Noncompliant"
    else
      echo "$guidance,$Release,$hostN,/etc/motd Ok - check for OS references,Compliant"
    fi
  fi
}

IP6OutboundTest () {
  Msg=$( $Sudo ip6tables --list -v -n )

  count=$( echo "$Msg" | wc -l )

  if [ $count -ne 14 ]
  then
    echo "not configured correctly - $count lines found"
    return 1
  fi
}

IP6Outbound () {
  guidance=$1

  if [ $hasSudo -ne 1 ]
  then
    echo "$guidance,$Release,$hostN,IP6Outbound requires root,Exception"
    return 1
  fi

  Msg=$( IP6OutboundTest )

  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,IP6OutboundTest $Msg,Exception"
    return 1
  fi

  echo "$guidance,$Release,$hostN,IP6OutboundTest OK === please check,Compliant"
}

KeyValueGE () {
  guidance=$1
  fileName="$2"
  key="$3"
  value=$4

  Buf="$( grep ^${key}[[:space:]] ${fileName} )"
  if [ -n "$Buf" ]
  then
    echo $Buf | while read k mat X
    do
      if [ $mat -ge $value ]
      then
        echo "$guidance,$Release,$hostN,$key >= $value,Compliant"
      else
        echo "$guidance,$Release,$hostN,$key < $value,Noncompliant"
      fi
    done
  else
    echo "$guidance,$Release,$hostN,${key} missing,Noncompliant"
  fi
}

KeyValueLE () {
  guidance=$1
  fileName="$2"
  key="$3"
  value=$4

  Buf="$( grep ^${key}[[:space:]] ${fileName} )"
  if [ -n "$Buf" ]
  then
    echo $Buf | while read k mat X
    do
      if [ $mat -le $value ]
      then
        echo "$guidance,$Release,$hostN,$key <= $value,Compliant"
      else
        echo "$guidance,$Release,$hostN,$key > $value,Noncompliant"
      fi
    done
  else
    echo "$guidance,$Release,$hostN,${key} missing,Noncompliant"
  fi
}

maxAuthTries () {
  guidance=$1
  MaxTries=$2

  if [ $hasSudo -ne 1 ]
  then
    echo "$guidance,$Release,$hostN,maxAuthTries requires root,Exception"
    return 1
  fi

  Buf="$( $Sudo grep ^MaxAuthTries /etc/ssh/sshd_config )"
  if [ -n "$Buf" ]
  then
    echo $Buf | while read X mat X
    do
      if [ $mat -le $MaxTries ]
      then
        echo "$guidance,$Release,$hostN,maxAuthTries = $m,Compliant"
      else
        echo "$guidance,$Release,$hostN,maxAuthTries = $m,Exception"
      fi
    done
  else
    echo "$guidance,$Release,$hostN,maxAuthTries missing,Exception"
  fi
}

MountConfigured () {
  guidance=$1
  mountName=$2

  Msg="`mountpoint $mountName`" 
  if [[ "$Msg" =~ "is a mountpoint" ]]
  then
    Stat="Compliant"
  else
    Stat="Noncompliant"
  fi

  echo "$guidance,$Release,$hostN,$Msg,$Stat"
}

MountDisabledTest () {
  mountName="$1"

  Msg=$( modprobe --dry-run --verbose $mountName )

  [ -z "$Msg" ] && echo "modprobe $mountName failed"

  echo "$Msg" | grep -v '^install /bin/true'

  lsmod | grep $mountName
}

MountDisabled () {
  guidance=$1
  mountName=$2

  Msg=$( MountDisabledTest $mountName | head -n1 )
  if [ -z "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,MountDisabledTest $mountName disabled,Compliant"
  else
    echo "$guidance,$Release,$hostN,MountDisabledTest $mountName not disabled,Noncompliant"
  fi
}

MountHasOption () {
  guidance=$1
  mountName=$2
  option="$3"

  Msg=`grep "^${mountName}[[:space:]].*[',',[:space:]]${option}[',',[:space:]]" /etc/fstab` 
  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,$mountName has $option option,Compliant"
  else
    echo "$guidance,$Release,$hostN,$mountName missing $option option,Noncompliant"
  fi
}

NoAutomountTest () {
  if [ -n "$( which systemctl 2> /dev/null )" ]
  then
    systemctl is-enabled autofs | grep -iw "^enabled"
  else
    chkconfig --list | grep autofs | grep -w on
  fi
}

NoAutomount () {
  guidance=$1

  Msg=$( NoAutomountTest )
  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,NoAutomountTest autofs enabled,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,NoAutomountTest autofs disabled,Compliant"
  fi
}

NoDupGIDs () {
  guidance=$1

  dupGIds=`cat /etc/group | tr ":" " " | awk '{print $3}' | sort -nk1 | uniq -c | awk '($1 > 1) {print $2}'`

  if [ -n "$dupGIds" ]
  then
    echo "$guidance,$Release,$hostN,NoDupGIDs duplicates exist,Noncompliant"
  else
     echo "$guidance,$Release,$hostN,NoDupGIDs OK,Compliant"
  fi
}

NoDupGroupNames () {
  guidance=$1

  dupNames=`cat /etc/group | tr ":" " " | awk '{print $1}' | sort -nk1 | uniq -c | awk '($1 > 1) {print $2}'`

  if [ -n "$dupNames" ]
  then
    echo "$guidance,$Release,$hostN,NoDupGroupNames duplicates exist,Noncompliant"
  else
     echo "$guidance,$Release,$hostN,NoDupGroupNames OK,Compliant"
  fi
}

NoDupUIDs () {
  guidance=$1

  dupIds=`cat /etc/passwd | tr ":" " " | awk '{print $3}' | sort -nk1 | uniq -c | awk '($1 > 1) {print $2}'`

  if [ -n "$dupIds" ]
  then
    echo "$guidance,$Release,$hostN,NoDupUIDs duplicates exist,Noncompliant"
  else
     echo "$guidance,$Release,$hostN,NoDupUIDs OK,Compliant"
  fi
}

NoDupUserNames () {
  guidance=$1

  dupNames=`cat /etc/passwd | tr ":" " " | awk '{print $1}' | sort -nk1 | uniq -c | awk '($1 > 1) {print $2}'`

  if [ -n "$dupNames" ]
  then
    echo "$guidance,$Release,$hostN,NoDupUserNames duplicates exist,Noncompliant"
  else
     echo "$guidance,$Release,$hostN,NoDupUserNames OK,Compliant"
  fi
}

NoExecOnRemovables () {
  guidance=$1
  stat="Compliant"
  Msg="NoExecOnRemovables OK"
  line=""

  line=$( grep "floppy\|cdrom\|dvdrom" /etc/fstab | while read line
  do
    if [[ ! "$line" =~ "noexec" ]]
    then
      echo "$line"
      break
    fi
  done )

  if [ -n "$line" ]
  then
    Msg=$( echo "$line" | tr ',' ' ' | tr -s " " )
    stat="Noncompliant"
  fi

  echo "$guidance,$Release,$hostN,$Msg,$stat"
}

NoForwardFiles () {
  guidance=$1

### does this need sudo? ###

  Msg=$(for dir in $( awk -F: '{print $6}' /etc/passwd | sort | uniq )
  do
    if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]
    then
      echo "dir/.forward"
    fi
  done)

  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,NoForwardFiles forward files found,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,NoForwardFiles no forward files found,Compliant"
  fi
}

NoWorldWritableTest () {
  if [ "$hasSudo" = "1" ]
  then
    df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' $Sudo find '{}' -xdev -type f -perm -0002 -ls 2>/dev/null | head -n5
  else
    df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 -ls 2>/dev/null | head -n5
  fi
}

NoWorldWritable () {
  guidance=$1

# $Sudo find / -xdev -perm +o=w ! \( -type d -perm +o=t \) ! -type l -print
# find / -perm -o+w ! -type l -ls 2>/dev/null | grep -v '/proc/'
# Msg="$( find / -perm -o+w ! -type l -ls 2>/dev/null | grep -v '/proc/' )"

  Msg=$( NoWorldWritableTest )
  if [ -n "$Msg" ]
  then
    echo "$Msg"
    echo $guidance,$Release,$hostN,World Writable files,Exception
  else
    echo "$guidance,$Release,$hostN,No World Writable files,Compliant"
  fi
}

PasswordChangeDate () {
  guidance=$1

  if [ $hasSudo -ne 1 ]
  then
    echo "$guidance,$Release,$hostN,PasswordChangeDate requires root,Exception"
    return 1
  fi

  currentDay=$( echo $(( $(date +%s) / 86400 )) )
  Msg=$( $Sudo cat /etc/shadow | tr ":" " " | awk '($3 > $currentDay) {print $1,$3}' )

  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,PasswordChangeDate future dates found,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,PasswordChangeDate OK,Compliant"
  fi
}

PasswordFields () {
  guidance=$1

  if [ $hasSudo -ne 1 ]
  then
    echo "$guidance,$Release,$hostN,PasswordFields requires root,Exception"
    return 1
  fi

  Msg=$( $Sudo grep '::.*:.*:.*:.*:.*:.*:.*$' /etc/shadow )

  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,PasswordFields accounts without passwords,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,PasswordFields OK,Compliant"
  fi
}

PasswordReuseTest () {

  Msg=$( egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth )
  if [ -z "$Msg" ]
  then
    echo "password\s+sufficient\s+pam_unix.so missing from /etc/pam.d/password-auth"
    return 1
  fi

  if [ -z "$( echo $Msg | awk -F= '($2 < 5)')" ]
  then
    echo $Msg
    return 1
  fi

  Msg=$( egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth )
  if [ -z "$Msg" ]
  then
    echo "^password\s+sufficient\s+pam_unix.so missing from /etc/pam.d/system-auth"
    return 1
  fi

  if [ -z "$( echo $Msg | awk -F= '($2 < 5)')" ]
  then
    echo $Msg
    return 1
  fi
}

PasswordReuse () {
  guidance=$1

  Msg=$( PasswordReuseTest | head -n1 )

  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,PasswordReuseTest $Msg,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,PasswordReuse OK,Compliant"
  fi
}

PkgInstalled () {
  guidance=$1
  pkg=$2

  if [ -n "`echo $PKGS | grep -o \:$pkg\:`" ]
  then
    echo "$guidance,$Release,$hostN,$pkg installed,Compliant"
  else
    echo "$guidance,$Release,$hostN,$pkg not installed,Noncompliant"
  fi 
}

Pkg2Installed () {
  guidance=$1
  pkg=$2

  if [ -n "`echo ${PKGS} | grep -o \:${pkg}\:`" ]
  then
    if [ -n "$3" ]
    then
      PkgInstalled $1 $3
    else
      echo "$guidance,$Release,$hostN,$pkg installed,Compliant"
    fi
  else
    echo "$guidance,$Release,$hostN,$pkg not installed,Noncompliant"
  fi
}

PkgMgrReposConfiguredTest () {
  if [ -n "$( which dnf 2>/dev/null )" ]
  then
    dnf repolist 2>&1 | grep -w Errno
  else
    yum repolist 2>&1 | grep -w Errno
  fi
}

PkgMgrReposConfigured () {
  guidance=$1

  Msg=$( PkgMgrReposConfiguredTest | head -n1 )
  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,PkgMgrReposConfigured failed,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,PkgMgrReposConfiguredTest OK,Compliant"
  fi
}

PkgNotInstalled () {
  guidance=$1
  pkg=$2

  if [ -n "`echo ${PKGS} | grep -o '\:${pkg}\:'`" ]
  then
    echo "$guidance,$Release,$hostN,$pkg installed,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,$pkg not installed,Compliant"
  fi 
}

RedHatSubscription () {
  guidance=$1

  if [ "$hasSudo" == "1" ]
  then
    Msg=`$Sudo subscription-manager status 2>/dev/null | grep "^Overall Status: Current"`
    if [ -n "$Msg" ]
    then 
      echo "$guidance,$Release,$hostN,subscription-manager current,Compliant"
    else
      echo "$guidance,$Release,$hostN,subscription-manager not current,Noncompliant"
    fi
  else
    echo "$guidance,$Release,$hostN,RedHatSubscription no $Sudo access,Exception"
  fi
}

RootGroup () {
  guidance=$1

  Msg="$( grep '^root:x:0:' /etc/group )"
  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,RootGroup OK,Compliant"
    return 1
  fi

  echo "$guidance,$Release,$hostN,RootGroup test failed,Noncompliant"
}

RootPathTest () {
# From https://secscan.acron.pl/centos7/6/2/6
  if [ "`echo $PATH | grep :: `" != "" ]; then 
    echo "Empty Directory in PATH (::)" 
  fi 
  if [ "`echo $PATH | grep :$`" != "" ]; then 
    echo "Trailing : in PATH" 
  fi 
  p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'` 
  set -- $p 
  while [ "$1" != "" ]; do
    if [ "$1" == "." ]; then
      echo "PATH contains ." 
      shift 
      continue 
    fi 
    if [ -d $1 ]; then
      dirperm=`ls -ldH $1 | cut -f1 -d" "` 
      if [ `echo $dirperm | cut -c6 ` != "-" ]; then
        echo "Group Write permission set on directory $1" 
      fi 
    if [ `echo $dirperm | cut -c9 ` != "-" ]; then
      echo "Other Write permission set on directory $1" 
    fi 
    dirown=`ls -ldH $1 | awk '{print $3}'` 
    if [ "$dirown" != "root" ] ; then
      echo $1 is not owned by root 
    fi 
    else 
      echo $1 is not a directory
    fi 
    shift 
  done
}

RootPath () {
  guidance=$1

  Msg=$( RootPathTest | head -n1 )

  if [ -n "$Msg" ]
  then
    echo "$Msg"
    #echo "$guidance,$Release,$hostN,RootPathTest() failed,Noncompliant"
    echo "$guidance,$Release,$hostN,RootPathTest() failed,Exception"
  else
    echo "$guidance,$Release,$hostN,RootPath OK,Compliant"
  fi
}

RootSystemConsole () {
  guidance=$1

  if [ $hasSudo -ne 1 ]
  then
    echo "$guidance,$Release,$hostN,RootSystemConsole requires root,Exception"
    return 1
  fi

  Msg="$( $Sudo grep -v ^console$ /etc/securetty )"
  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,RootSystemConsole on unsecure devices,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,RootSystemConsole only on console,Compliant"
  fi
}

SELinuxNotDisabled () {
  guidance=$1

  if [ -n "$( sestatus | grep enabled )" ]
  then
    echo "$guidance,$Release,$hostN,SELinux enabled,Compliant"
  else
    echo "$guidance,$Release,$hostN,SELinux disabled,Exception"
  fi
}

SEPolicyConfigured () {
  guidance=$1

  if [ "$Release" == "RH8" ]
  then
    echo "$guidance,$Release,$hostN,SEPolicyConfigured RedHat 8 NA,Compliant"
    return 1
  fi

  if [ -n $( grep "^SELINUXTYPE=targeted\s*$" /etc/selinux/config ) ]
  then
    echo "$guidance,$Release,$hostN,SEPolicyConfigure,Compliant"
  else
    echo "$guidance,$Release,$hostN,SEPolicyConfigure,Exception"
  fi
}

ShellTimeoutTest () {
  Msg=$( grep TMOUT= /etc/profile.d/*.sh /etc/profile /etc/bashrc )
  if [ -z "$Msg" ]
  then
    echo "TMOUT= not found"
    return 1
  fi

  if [ $( echo $Msg | grep -c TMOUT= ) -gt 1 ]
  then
    echo "more than 1 TMOUT found"
    return 1
  fi

  Msg1=$( echo "$Msg" | awk -F= '($2 > 900 || $2 < 10) {print}' )
  if [ ${Msg1} ]
  then
    echo ${Msg}
  fi
}

ShellTimeout () {
  guidance=$1

  Msg=$( ShellTimeoutTest | head -n1 )

  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,ShellTimeout $Msg ===,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,ShellTimeout OK ===,Compliant"
  fi
}

SingleUserAuth () {
  guidance=$1
  Msg="SingleUserAuth "
  stat="Compliant"

  if [ "$Release" == "RH6" ] || [ "$Release" == "RH5" ]
  then
    echo "$guidance,$Release,$hostN,SingleUserAuth RHEL6 NA,Exception"
    return 1
  fi

  if [ -e /usr/lib/systemd/system/rescue.service ]
  then
    if [ -n "$( grep '^ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue$' /usr/lib/systemd/system/rescue.service )" ]
    then
      if [ -e /usr/lib/systemd/system/emergency.service ]
      then
        if [ -z "$( grep '^ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency$' /usr/lib/systemd/system/emergency.service )" ]
        then
          Msg="ExecStart missing from /usr/lib/systemd/system/emergency.service"
          stat="Noncompliant"
        fi
      else
        Msg="/usr/lib/systemd/system/emergency.service is missing"
        stat="Noncompliant"
      fi
    else
      Msg="ExecStart missing from /usr/lib/systemd/system/rescue.service"
      stat="Noncompliant"
    fi
  else
    Msg="/usr/lib/systemd/system/rescue.service missing"
    stat="Noncompliant"
  fi

  echo "$guidance,$Release,$hostN,$Msg,$stat"
}

SSHIdleTimeout () {
  guidance=$1

  if [ -e "/etc/profile.d/tmout.sh" ]
  then
    echo "$guidance,$Release,$hostN,tmout.sh exists - site policy OK,Compliant"
    return 1  
  fi

  if [ "$hasSudo" -ne 1 ]
  then
    echo "$guidance,$Release,$hostN,SSHIdleTimeout requires root,Exception"
    return 1
  fi

  Msg="$( $Sudo awk '/^ClientAliveInterval / && $2<=300 && $2>=0 {print $0}' /etc/ssh/sshd_config )"
  if [ -z "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,^ClientAliveInterval missing,Noncompliant"
    return 1
  fi

  Msg="$( $Sudo awk '/^ClientAliveCountMax / && $2<=3 && $2>=0 {print $0}' /etc/ssh/sshd_config )"
  if [ -z "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,^ClientAliveCountMax missing,Noncompliant"
    return 1
  fi

  echo "$guidance,$Release,$hostN,SSHIdleTimeout OK,Compliant"
}

SSHPam () {
  guidance=$1

  if [ $hasSudo -ne 1 ]
  then
    echo "$guidance,$Release,$hostN,SSHPam requires root,Exception"
    return 1
  fi

  if [ -n "$( $Sudo grep -i '^USEPam yes$' /etc/ssh/sshd_config )" ]
  then
    echo "$guidance,$Release,$hostN,SSHPam OK,Compliant"
  else
    echo "$guidance,$Release,$hostN,SSHPam USEPam missing,Noncompliant"
  fi
}

SuCmdRestrictedTest () {
   grep pam_wheel.so /etc/pam.d/su | grep -v "^\#" | grep -v "auth.*required.*pam_wheel.so.*use_uid"
   grep wheel /etc/group | grep -v "^\#" | grep -v '^wheel:x:10:root$'
}

SuCmdRestricted () {
  guidance=$1

  Msg=$( SuCmdRestrictedTest | head -n1 )

  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,SuCmdRestrictedTest failed,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,SuCmdRestrictedTest OK,Compliant"
  fi
}

SystemAcctsSecureTest () {
# from https://secscan.acron.pl/centos7/5/4/2

  egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!="oracle" && $3<1000 && $7!="/usr/sbin/nologin" && $7!="/sbin/nologin" && $7!="/bin/false") {print}'
}

SystemAcctsSecure () {
  guidance=$1

  Msg=$( SystemAcctsSecureTest | head -n1 )

  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,SystemAcctsSecureTest failed,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,SystemAcctsSecureTest OK,Compliant"
  fi
}

UID0 () {
  guidance=$1

  Msg=`grep -v 'root:' /etc/passwd | awk -F ':' '$3 == "0" {print $0}'`
  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,UID0 failed,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,UID0 OK,Compliant"
  fi
}

USBDisabled () {
  guidance=$1

  if [ ! -e /etc/modprobe.d/usb-storage.conf ]
  then
    echo "$guidance,$Release,$hostN,/etc/modprobe.d/usb-storage.conf missing,Noncompliant"
    return 1
  fi

  if [ -z "grep '^install usb-storage /bin/true$' /etc/modprobe.d/usb-storage.conf" ]
  then
    echo "$guidance,$Release,$hostN,/etc/modprobe.d/usb-storage.conf missing ^install usb-storage /bin/true$,Noncompliant"
    return 1
  fi

  echo "$guidance,$Release,$hostN,USBDisabled,Compliant"
}

UserDirOwnersTest () {
  cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir
  do
    if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" ]
    then
      owner=$(stat -L -c "%U" "$dir") 
      if [ "$owner" != "$user" ]
      then
        echo "$dir user $user is owned by $owner." 
      fi 
    fi 
  done
}

UserDirOwners () {
  guidance=$1

  Msg="$( UserDirOwnersTest | head -n1 )"

  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,UserDirOwners failed,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,UserDirOwners OK,Compliant"
  fi
}

UserDirPermissionsTest () {
  Sudo="$1"
# from https://secscan.acron.pl/centos7/6/2/8

  for dir in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($1 != "oracle" && $7 != "/usr/sbin/nologin" && $7 != "/sbin/nologin") { print $6 }'`; do
  #for dir in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/sbin/nologin") { print $6 }'`; do
    dirperm=`$Sudo ls -ld $dir 2>/dev/null | cut -f1 -d" "` 
    if [ "`echo $dirperm | cut -c6 `" != "-" ]; then
      echo "Group Write permission set on directory $dir" 
    fi 
    if [ "`echo $dirperm | cut -c8 `" != "-" ]; then 
      echo "Other Read permission set on directory $dir" 
    fi 
    if [ "`echo $dirperm | cut -c9 `" != "-" ]; then
      echo "Other Write permission set on directory $dir" 
    fi
    if [ "`echo $dirperm | cut -c10 `" != "-" ]; then
      echo "Other Execute permission set on directory $dir" 
    fi 
  done
}

UserDirPermissions () {
  guidance=$1

  #Msg=`find /export/home/ -maxdepth 1 -type d -exec stat -c "%a %n" {} \;`

  if [ "$hasSudo" -ne "1" ]
  then
    Msg=$( UserDirPermissionsTest | head -n1 )
    if [ -n "$Msg" ]
    then
      echo "$guidance,$Release,$hostN,UserDirPermissionsTest failed,Noncompliant"
    else
      echo "$guidance,$Release,$hostN,UserDirPermissionsTest OK (without sudo),Exception"
    fi
    return 1
  fi

  Msg=$( UserDirPermissionsTest $Sudo | head -n1 )

  if [ -n "$Msg" ]
  then
    echo "$Msg"
    echo "$guidance,$Release,$hostN,UserDirPermissionsTest returned noncompliant,Exception"
    #echo "$guidance,$Release,$hostN,UserDirPermissionsTest returned noncompliant,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,UserDirPermissionsTest OK,Compliant"
  fi
}

UserDirsTest () {
# from https://secscan.acron.pl/centos7/6/2/7
  cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir X
  do
    if [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
      echo "The home directory ($dir) of user $user does not exist." 
    fi 
  done
}

UserDirs () {
  guidance=$1

  Msg=$( UserDirsTest | head -n1 )

  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,UserDirs home directories missing,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,UserDirs OK,Compliant"
  fi
}

UseShadowPasswords () {
  guidance=$1

  Msg=`awk -F ':' '$2 != "x" {print $0}' /etc/passwd`
  if [ -n "$Msg" ]
  then
    echo "$guidance,$Release,$hostN,UseShadowPasswords failed,Noncompliant"
  else
    echo "$guidance,$Release,$hostN,UseShadowPasswords OK,Compliant"
  fi
}

XD_NXSupport () {
  guidance=$1

  if [ "$Release" == "RH8" ]
  then
    echo "$guidance,$Release,$hostN,RedHat 8 NA,Compliant"
    return 1
  fi

  if [ -n "$(  uname -r | grep x86_64 )" ]
  then
    echo "$guidance,$Release,$hostN,XD_NXSupport x86_64 Operating System,Compliant"
    return 1
  fi

  if [ -z "`grep -iwo PAE /proc/cpuinfo`" ]
  then
    echo "$guidance,$Release,$hostN,XD_NXSupport pae not found,Noncompliant"
    return 1
  fi

  if [ -z "`uname -r | grep -i pae`" ]
  then
    echo "$guidance,$Release,$hostN,XD_NXSupport kernel pae not found,Noncompliant"
    return 1
  fi

  echo "$guidance,$Release,$hostN,XD_NXSupport pae found,Compliant"
}


RHELComplianceTest ()
{
  MountDisabled 1 cramfs
  MountDisabled 2 udf
  MountConfigured 3 /tmp
  MountHasOption 4 tmp noexec
  MountHasOption 5 tmp nodev
  MountHasOption 6 tmp nosuid
  NoExecOnRemovables 15
  NoAutomount 19
  USBDisabled 20
  GPGKeyConfigured 21
  PkgMgrReposConfigured 22
  GPGCheck 23
  RedHatSubscription 24
  PkgInstalled 25 sudo
  BootLoaderPassword 30
  [ -e /boot/grub/grub.conf ] && CheckPermissions 31 /boot/grub/grub.conf 600 || CheckPermissions 31 "/boot/grub2/user.cfg" 600
  SingleUserAuth 32
  XD_NXSupport 34
  [ "$Release" == "RH8" ] && echo "37,$Release,$hostN,libselinux RedHat 8 NA,Compliant" || PkgInstalled 37 libselinux
  #SELinuxNotDisabled 38
  #SEPolicyConfigured 39
  [ "$Release" == "RH8" ] && echo "42,$Release,$hostN,setroubleshoot RedHat 8 NA,Compliant" || PkgNotInstalled 42 setroubleshoot
  [ "$Release" == "RH8" ] && echo "43,$Release,$hostN,mcstrans RedHat 8 NA,Compliant" || PkgNotInstalled 43 mcstrans
  LocalLoginWarningBanner 45
  CheckPermissions 47 /etc/motd 644
  CheckPermissions 48 /etc/issue 644
  CheckPermissions 49 /etc/issue.net 644
  CheckUpdates 50
  [ "$Release" == "RH8" ] && echo "51,$Release,$hostN,CheckDM RedHat 8 NA,Compliant" || CheckGDM 51
  PkgNotInstalled 52 xinetd
  CheckTimeSync 53
  [ "$Release" == "RH8" ] && echo "55,$Release,$hostN,CheckNTP RedHat 8 NA,Compliant" || CheckNTP 55
  [ "$Release" == "RH8" ] && echo "58,$Release,$hostN,cups RedHat 8 NA,Compliant" || PkgNotInstalled 58 cups
  [ "$Release" == "RH8" ] && echo "59,$Release,$hostN,dhcp RedHat 8 NA,Compliant" || PkgNotInstalled 59 dhcp
  [ "$Release" == "RH8" ] && echo "60,$Release,$hostN,openldap-servers RedHat 8 NA,Compliant" || PkgNotInstalled 60 openldap-servers
  [ "$Release" == "RH8" ] && echo "63,$Release,$hostN,bind RedHat 8 NA,Compliant" || PkgNotInstalled 63 bind
  [ "$Release" == "RH8" ] && echo "64,$Release,$hostN,vsftp RedHat 8 NA,Compliant" || PkgNotInstalled 64 vsftpd
  [ "$Release" == "RH8" ] && echo "65,$Release,$hostN,httpd RedHat 8 NA,Compliant" || PkgNotInstalled 65 httpd
  [ "$Release" == "RH8" ] && echo "66,$Release,$hostN,dovecot RedHat 8 NA,Compliant" || PkgNotInstalled 66 dovecot
  [ "$Release" == "RH8" ] && echo "67,$Release,$hostN,samba RedHat 8 NA,Compliant" || PkgNotInstalled 67 samba
  [ "$Release" == "RH8" ] && echo "68,$Release,$hostN,squid RedHat 8 NA,Compliant" || PkgNotInstalled 68 squid
  [ "$Release" == "RH8" ] && echo "71,$Release,$hostN,rsync RedHat 8 NA,Compliant" || PkgNotInstalled 71 rsync
  [ "$Release" == "RH8" ] && echo "72,$Release,$hostN,RedHat 8 NA,Compliant" || PkgNotInstalled 72 ypbind
  [ "$Release" == "RH8" ] && echo "73,$Release,$hostN,telnet-server RedHat 8 NA,Compliant" || PkgNotInstalled 73 telnet-server
  PkgNotInstalled 74 ypbind
  [ "$Release" == "RH8" ] && echo "75,$Release,$hostN,rsh RedHat 8 NA,Compliant" || PkgNotInstalled 75 rsh
  [ "$Release" == "RH8" ] && echo "76,$Release,$hostN,talk RedHat 8 NA,Compliant" || PkgNotInstalled 76 talk
  PkgNotInstalled 77 telnet
  CheckIP6Ads 91
  [ "$Release" == "RH8" ] && echo "92,$Release,$hostN,firewalld iptables RedHat 8 NA,Compliant" || Pkg2Installed 92 firewalld iptables
  [ "$Release" == "RH8" ] && echo "93,$Release,$hostN,RedHat 8 NA,Compliant" || PkgNotInstalled 93 iptables-services
  [ "$Release" == "RH8" ] && echo "94,$Release,$hostN,RedHat 8 NA,Compliant" || PkgNotInstalled 94 nftables
  [ "$Release" == "RH8" ] && echo "99,$Release,$hostN,RedHat 8 NA same as 93?,Compliant" || PkgNotInstalled 99 iptables-services
  IP6DefaultDeny 114 "INPUT DROP" "OUTPUT DROP" "FORWARD DROP"
  IP6Loopback 115 "INPUT -i lo -j ACCEPT" "OUTPUT -o lo -j ACCEPT" "INPUT -s ::1 -j DROP"
  IP6Outbound 116 # "OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT" "OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT" "OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT" "INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT" "INPUT -p udp -m state --state ESTABLISHED -j ACCEPT" "INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT"
  IP6OpenPorts 117
  [ "$Release" == "RH8" ] && echo "118,$Release,$hostN,/etc/sysconfig/ip6tables RedHat 8 NA,Compliant" || IP6CheckFile 118 "/etc/sysconfig/ip6tables"
  [ "$Release" == "RH8" ] && echo "119,$Release,$hostN,ip6tables RedHat 8 NA,Compliant" || CheckEnabled 119 "ip6tables" "Exception"
  PkgInstalled 120 rsyslog
  [ "$Release" == "RH8" ] && echo "121,$Release,$hostN,rsyslog RedHat 8 NA,Compliant" || CheckEnabled 121 "rsyslog"
  CheckRSysLog 123 "/etc/rsyslog.conf" "/etc/rsyslog.d/*"
  CheckLogsToRemote 124
  CheckLogPermissions 129
  CheckLogrotate 130
  [ "$Release" == "RH8" ] && echo "131,$Release,$hostN,crond RedHat 8 NA,Compliant" || CheckEnabled 131 "crond"
  CheckCron 132 "$PKGS"
  CheckPermissions1 140 "/etc/ssh/sshd_config" "600 root root"
  ##CheckSSHPermissions 141 "600 root root"
  CheckSSHPrivatePermissions 141 "644 root root"
  CheckSSHPublicPermissions 142 "644 root root"
  maxAuthTries 145 4
  SSHIdleTimeout 154
  SSHPam 157
  CheckPasswordReq 160
  PasswordReuse 163
  SystemAcctsSecure 164
  RootGroup 165
  [ "$Release" == "RH8" ] && echo "166,$Release,$hostN,ShellTimeout RedHat 8 NA,Compliant" || ShellTimeout 166
  [ "$Release" == "RH8" ] && echo "167,$Release,$hostN,DefaultUMask RedHat 8 NA,Compliant" || DefaultUmask 167
  KeyValueLE 168 "/etc/login.defs" "PASS_MAX_DAYS" 365
  [ "$Release" == "RH8" ] && echo "169,$Release,$hostN,PASS_MIN_DAYS RedHat 8 NA,Compliant" || KeyValueGE 169 "/etc/login.defs" "PASS_MIN_DAYS" 1
  KeyValueLE 170 "/etc/login.defs" "PASS_WARN_AGE" 7
  PasswordChangeDate 172
  RootSystemConsole 173
  SuCmdRestricted 174
  CheckPermissions2 175 /etc/passwd 0133
  CheckPermissions2 176 /etc/shadow 037
  CheckPermissions2 177 /etc/group 0133
  CheckPermissions2 178 /etc/gshadow 037
  CheckPermissions2 180 /etc/shadow- 0177
  CheckPermissions2 181 /etc/group- 0133
  CheckPermissions2 182 /etc/gshadow- 011
  NoWorldWritable 183
  [ "$Release" == "RH8" ] && echo "188,$Release,$hostN,RedHat 8 NA,Compliant" || UseShadowPasswords 188
  [ "$Release" == "RH8" ] && echo "189,$Release,$hostN,PasswordFields RedHat 8 NA,Compliant" || PasswordFields 189
  UID0 190
  RootPath 191
  UserDirs 192
  UserDirPermissions 193
  UserDirOwners 194
  NoForwardFiles 196
  CheckGroups 200
  NoDupUIDs 201
  NoDupGIDs 202
  NoDupUserNames 203
  NoDupGroupNames 204
  EmptyShadowGroup 205
}

RHELComplianceTest_1 ()
{
  NoAutomount 19  
  [ "$Release" == "RH8" ] && echo "121,$Release,$hostN,rsyslog RedHat 8 NA,Compliant" || CheckEnabled 121 "rsyslog"
  [ "$Release" == "RH8" ] && echo "131,$Release,$hostN,crond RedHat 8 NA,Compliant" || CheckEnabled 131 "crond"
  UserDirPermissions 193
}

if [ -n "$1" ]
then
  while (( "$#" ))
  do
    [ "$1" != "X" ] && echo "`$1`"
    shift 1
  done
else
  #RHELComplianceTest
  RHELComplianceTest_1
fi
