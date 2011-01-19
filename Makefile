# 
# 
# ircDDB-mheard
# 
# Copyright (C) 2011   Michael Dirska, DL1BFF (dl1bff@mdx.de)
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



CFLAGS=-Wall

LDLIBS=-lpcap

all: ircDDB-mheard


pidfile.o: libutil.h

flopen.o: libutil.h

ircDDB-mheard.o: libutil.h ircddbmhd_version.h

dstar_dv.o: dstar_dv.h golay23.h

golay23.o: golay23.h


ircDDB-mheard: ircDDB-mheard.o pidfile.o flopen.o dstar_dv.o golay23.o


ircddbmhd_version.h:
	touch ircddbmhd_version.h



clean:
	rm -f *.o

distclean: clean
	rm -f ircDDB-mheard ircddbmhd_version.h

rpm:
	rpmbuild -ba ircddbmhd.spec
	createrepo i386

test_dv: test_dv.o dstar_dv.o golay23.o


install: ircDDB-mheard
	install ircDDB-mheard $(DESTDIR)/usr/sbin/ircddbmhd
	install -d $(DESTDIR)/var/run/ircddbmhd

