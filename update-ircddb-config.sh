#!/bin/sh
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

transfer_numeric_value() {

  if [ $# != 4 ]
  then
    return
  fi

  if [ ! -f "$1" ]
  then
    return
  fi

  if [ ! -f "$3" ]
  then
    return
  fi

  if ! grep -q "^[[:space:]]*${2}=[1-9][0-9]*" "$1"
  then
    return
  fi

  VALUE=` gawk '
   /^[[:space:]]*'"$2"'=[1-9][0-9]*/ {  
     match( $0, "^[[:space:]]*'"$2"'=([1-9][0-9]*)", a)
     print a[1]
     exit
   } ' < "$1" ` 

  if [ "x$VALUE" = "x" ]
  then
    return
  fi

  if grep -q "^[[:space:]]*${4}=[1-9][0-9]*" "$3"
  then
    if grep -q "^[[:space:]]*${4}=${VALUE}[[:space:]]*$" "$3"
    then
      echo "${4}=$VALUE exists already in $3"
    else
      echo "replacing value for $4 with $VALUE in $3"

      echo -e ",s/^[[:space:]]*${4}=[1-9][0-9]*/${4}=$VALUE/\nwq" | ed -s "$3"
    fi
  else
    echo "adding ${4}=$VALUE to $3"
    echo "${4}=$VALUE" >> "$3"
  fi


}


transfer_numeric_value /etc/default/ircddbmhd MHEARD_UDP_PORT /opt/ircDDB/ircDDB.properties mheard_udp_port



