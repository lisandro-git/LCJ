#!/bin/bash
is_dir() {
  if [ -d "$1" ]
    then
      return 0 # true
    else
      return 1 # false
  fi
}

echo "It is not possible to build for arm64 because of my go version (1.15.6), the only darwin build is armd64"

RW_path=/root/y/
if ! [ "${RW_path:(-1)}" = "/" ] # in case that you forget the trailing / in the path
then
  RW_path=$RW_path/
fi

darwin_build=0
linux64_build=0
linux32_build=0
windows32_build=0

for dir in $RW_path*; do    # list directories in the form "/tmp/dirname/"
  for file in $dir/*; do
    if ! is_dir $file; then
      len_file=${#file##*/}

      if (( $len_file > 1 )); then # if len(file) >= 2
        file_name=${file##*/}
        file_first_char=${file_name:0:1}
        if (( darwin_build >= 50 )) # build one darwin executable each 50 files
        then
          env GOOS=darwin GOARCH=amd64 go build -i -o ${file:0:-3}a6  $file
          darwin_build=0
        fi

        if (( linux64_build >= 10 )) # build one linux64 executable each 10 files
        then
          env GOOS=linux GOARCH=amd64 go build -i -o ${file:0:-3}e6  $file
          linux64_build=0
        fi
        if (( linux32_build >= 150 )) # build one linux32 executable each 150 files
        then
          env GOOS=linux GOARCH=386 go build -i -o ${file:0:-3}e3  $file
          linux32_build=0
        fi

        if (( windows32_build >= 100 )) # build one windows32 executable each 100 files
        then
          env GOOS=windows GOARCH=386 go build -i -o ${file:0:-3}3.exe  $file
          windows32_build=0
        fi

        env GOOS=windows GOARCH=amd64 go build -i -o ${file:0:-3}6.exe  $file # windows64 is always created

        darwin_build=$((darwin_build+1))
        linux64_build=$((linux64_build+1))
        linux32_build=$((linux32_build+1))
        windows32_build=$((windows32_build+1))
      fi
    fi
  done
done
