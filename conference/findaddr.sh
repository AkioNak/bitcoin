#!/bin/bash
BC2DIR=./
if [ -e "$(dirname $0)" ]; then
    cd $(dirname $0)/../src
elif [ -e "$HOME/bc2/bc2/src" ]; then
    cd $HOME/bc2/bc2/src
else
    echo "Can't find bc2 binary. Using path."
    BC2DIR=
fi
BC2=$BC2DIR"bitcoin-cli"
findaddress=$1
blockcount=$(./bitcoin-cli getblockcount)
for i in $(seq $blockcount -1 1); do
    echo -n -e "$i\r"
    $BC2 getblock $(./bitcoin-cli getblockhash $i) | jq .tx > x
    while read p; do
	if [ "$p" != "[" ] && [ "$p" != "]" ]; then
	    $BC2 getrawtransaction ${p:1:64} 1 > y
	    grep $findaddress y &>/dev/null
	    if [ $? -eq 0 ]; then
		echo $p
	    fi
	fi
    done < x
done
