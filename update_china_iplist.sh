#!/bin/sh

cd "$(dirname "$0")"

if [ -f "/proc/sys/kernel/random/uuid" ]; then
    tmp_file="/tmp/delegated-$(cat /proc/sys/kernel/random/uuid | cut -b '1-8').txt"
else
    tmp_file="/tmp/delegated-$(dd if=/dev/urandom bs=1 count=6 2>/dev/null | base64).txt"
fi
wget 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest' -O "$tmp_file" || { rm -rf "$tmp_file"; exit 1; }

cat "$tmp_file" | awk -F '|' '{if($2=="CN" && $3=="ipv4"){print($4"/"32-log($5)/log(2))}}' >china_ipv4.lst

cat "$tmp_file" | awk -F '|' '{if($2=="CN" && $3=="ipv6"){print($4"/"128-$5)}}' >china_ipv6.lst

rm -rf "$tmp_file"
