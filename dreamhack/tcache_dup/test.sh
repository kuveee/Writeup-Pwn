#!/bin/bash

# Logging Functions
function log()     { echo -e "\e[32m[*]\e[0m $@"; }
function error()   { echo -e "\e[31m[!]\e[0m $@"; exit 1; }
function warn()   { echo -e "\e[33m[x]\e[0m $@"; }
function msg()     { echo -e "\e[34m[+]\e[0m $@"; }
function msgln()     { echo -en "\e[34m[+]\e[0m $@"; }

function validate_and_extract() {

	# This function checks if $1 is a valid file. If it is, returns it.
	# If not, it finds the name, and returns the first matched result
	# if it's a valid file, otherwise errors out.

	if [ ! -z "$1" ]; then
		docker exec -it $_id "ls -l $1" 2>&1 >/dev/null
		[[ $? != 0 ]] && error "$1 is an invalid path. Please check."
		c_path="$1"
	fi

	if [ -z "$c_path" ]; then
		path=$(docker exec -it "$CONTAINER_NAME" sh -c "find / -name $2 -exec realpath {} \; 2>/dev/null")
		[[ $? != 0 && $? != 1 ]] && error "Unable to extract $2 path. Possible error: $path"
		c_path="${path%?}"
	fi
	
	[ -z "$c_path" ] && error "Unable to extract path. Manual intervention needed. Or maybe \"$2\" is not a valid file."
	echo $c_path
}

# modifiable vars ##
# Name of the image that will be created
IMAGE_NAME="temp_challenge"

# Name of the running container
CONTAINER_NAME="temp"

# Name and path of the output file:
OUT_FILE_LIBC="$(pwd)/libc.so.6"
OUT_FILE_LD="$(pwd)/ld.so.2"

# Optional: You can specify the path to libc/ld inside the docker container:
LIBC_PATH=""
LD_PATH=""

[[ $# != 2 ]] && error "Usage: $0 <Dockerfile> <Binary to patch>"
file="$1"
binary="$2"
[ ! -f "$file" ] && error "$1 is not a valid file. Please check."
[ ! -f "$binary" ] && error "$2 is not a valid file. Please check."

# precautionary measure
(docker ps | grep "$CONTAINER_NAME") 2>&1 >/dev/null
if [[ $? == 0 ]]; then
	warn "Found a container running with name $CONTAINER_NAME. Stopping it before continuing"
	docker stop "$CONTAINER_NAME" 2>&1 >/dev/null
fi

# Extract `FROM` statement, and creating another file with only the IMAGE, and a `sleep` entrypoint:
# Only get the first result.
from=$(cat "$file" | grep -i "^FROM" | cut -d $'\n' -f1)

img_name=`echo "$from" | grep -ioE '((theflash.*|ubuntu.*|debian.*|fedora.*|arch.*|python.*|php.*|apache.*):[^ \n]+)'`
msg "Extracted Image from \"$file\": $img_name"

# Delete the temp file if already exists.
tmp_dir=$(mktemp -d)
tmp_file=$(mktemp "$tmp_dir/temp_Docker_XXX")

[ -f "$tmp_file" ] && rm -f "$tmp_file"

echo "FROM $img_name" > "$tmp_file"
echo 'ENTRYPOINT ["sleep", "1000"]' >> "$tmp_file"

log "Wrote temporary Dockerfile: $tmp_file"
log "Building image $IMAGE_NAME."
docker build -f "$tmp_file" -t "$IMAGE_NAME" . 2>&1 >/dev/null

log "Built image with name: $IMAGE_NAME"

_id=$(docker run -d --rm -q --name "$CONTAINER_NAME" "$IMAGE_NAME")
msg "Ran container ($CONTAINER_NAME) with id $_id"

libc=""
ld=""

libc=`validate_and_extract "$LIBC_PATH" "libc.so.6"`
ld=`validate_and_extract "$LD_PATH" "ld-*"`

msg "Found libc: at $libc"
msg "Found ld: at $ld"

docker cp "$_id":"$libc" "$OUT_FILE_LIBC" 2>&1 >/dev/null
[[ $? != 0 ]] && warn "Unable to copy libc from the container :(" || msg "Copied libc from \"$libc\" to \"$OUT_FILE_LIBC\""

docker cp "$_id":"$ld" "$OUT_FILE_LD" 2>&1 >/dev/null
[[ $? != 0 ]] && warn "Unable to copy ld from the container :(" || msg "Copied ld from \"$ld\" to \"$OUT_FILE_LD\""

log "Cleaning up...."
docker stop "$CONTAINER_NAME" 2>&1 >/dev/null
msg "Stopped ($CONTAINER_NAME) $_id"

if [[ $DELETE != 0 ]]; then
	docker rmi "$IMAGE_NAME" 2>&1 >/dev/null
	[[ $? != 0 ]] && error "Unable to delete $IMAGE_NAME"
	msg "Deleted $IMAGE_NAME"
fi

# Using patchelf to patch the binary to use the corresponding libc and LD:
command -v "patchelf" 2>&1 >/dev/null
[[ $? != 0 ]] && error "$patcher not found in PATH. Please check."
msg "Patching $binary"
cp "$binary" "$binary-patched"
[[ $? != 0 ]] && warn "Unable to make clone of the file. Modifying original." || binary="$binary-patched"
patchelf --set-interpreter "$OUT_FILE_LD" --set-rpath . "$binary"
[[ $? != 0 ]] && error "An error occurred when running $patcher."
msg "Done patching binary: $binary"
