#
#
# ircDDB-mheard
#
# Copyright (C) 2010   Michael Dirska, DL1BFF (dl1bff@mdx.de)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#



Name: ircddbmhd
Version: 1.3
Release: 8
License: GPLv2
Group: Networking/Daemons
Summary: ircDDB-mheard daemon
URL: http://ircddb.net
Packager: Michael Dirska DL1BFF <dl1bff@mdx.de>
Requires: libpcap >= 0.9
Source0: dl1bff-ircDDB-mheard-v1.3-1-g78238bb.tar.gz
BuildRoot: %{_tmppath}/%{name}-root
BuildRequires: libpcap-devel

%description
The ircDDB-mheard daemon captures IP packets from an RP2C
DSTAR controller and sends its findings to a local UDP port.


%prep
%setup -n dl1bff-ircDDB-mheard-78238bb
echo "#define IRCDDBMHD_VERSION \"rpm:%{name}-%{version}-%{release}\"" > ircddbmhd_version.h



%build
make CFLAGS="$RPM_OPT_FLAGS"


%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/%{_sbindir}
mkdir -p %{buildroot}/etc/default
cp ircDDB-mheard %{buildroot}/%{_sbindir}/%{name}
cp etc_default_ircddbmhd %{buildroot}/etc/default/%{name}
mkdir -p %{buildroot}/var/run/%{name}
mkdir -p %{buildroot}/etc/init.d
cp centos_etc_initd_ircddbmhd %{buildroot}/etc/init.d/%{name}

%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root)
%config /etc/default/%{name}
%attr(755,root,root) %{_sbindir}/%{name}
%dir /var/run/%{name}
%attr(755,root,root) /etc/init.d/%{name}
%doc README COPYING LICENSE

%pre
if [ $1 -eq 2 ]; then
  /sbin/service %{name} stop
  /bin/sleep 2
fi


%preun
if [ $1 -eq 0 ]; then
  /sbin/service %{name} stop
  /sbin/chkconfig --del %{name}
fi


%post
if [ $1 -eq 1 ]; then
  /sbin/chkconfig --add %{name}
fi
if [ $1 -eq 2 ]; then
  /sbin/service %{name} start
fi



